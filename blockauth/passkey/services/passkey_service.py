"""
Passkey Service for BlockAuth

Main service implementing WebAuthn registration and authentication.
Uses py-webauthn library for protocol implementation.
"""

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import AttestationConveyancePreference
from webauthn.helpers.structs import AuthenticatorAttachment as WebAuthnAuthenticatorAttachment
from webauthn.helpers.structs import AuthenticatorSelectionCriteria
from webauthn.helpers.structs import AuthenticatorTransport as WebAuthnAuthenticatorTransport
from webauthn.helpers.structs import PublicKeyCredentialDescriptor, PublicKeyCredentialType
from webauthn.helpers.structs import ResidentKeyRequirement as WebAuthnResidentKeyRequirement
from webauthn.helpers.structs import UserVerificationRequirement as WebAuthnUserVerificationRequirement

from ..config import get_passkey_config
from ..constants import AuthenticatorAttachment, ChallengeType
from ..exceptions import (
    CounterRegressionError,
    CredentialNotFoundError,
    CredentialRevokedError,
    InvalidCredentialDataError,
    InvalidOriginError,
    MaxCredentialsReachedError,
    SignatureVerificationError,
)
from ..storage.base import CredentialData, ICredentialStore
from ..storage.django_storage import DjangoCredentialStore
from ..storage.memory_storage import MemoryCredentialStore
from ..utils import base64url_encode, format_aaguid, generate_user_handle
from .challenge_service import ChallengeService


@dataclass
class RegistrationResult:
    """Result of successful registration"""

    credential_id: str
    credential_id_b64: str
    public_key: str
    sign_count: int
    aaguid: str
    attestation_object: str
    user_verified: bool
    backup_eligible: bool
    backup_state: bool


@dataclass
class AuthenticationResult:
    """Result of successful authentication"""

    user_id: Any
    credential_id: str
    sign_count: int
    user_verified: bool
    backup_eligible: bool
    backup_state: bool


class PasskeyService:
    """
    Main service for WebAuthn passkey operations.

    Provides methods for:
    - Generating registration options
    - Verifying registration responses
    - Generating authentication options
    - Verifying authentication responses
    """

    def __init__(
        self,
        credential_store: Optional[ICredentialStore] = None,
        challenge_service: Optional[ChallengeService] = None,
    ):
        """
        Initialize PasskeyService.

        Args:
            credential_store: Optional custom credential store
            challenge_service: Optional custom challenge service
        """
        self._config = get_passkey_config()

        # Initialize credential store
        if credential_store:
            self._credential_store = credential_store
        elif self._config.storage_backend == "memory":
            self._credential_store = MemoryCredentialStore()
        else:
            self._credential_store = DjangoCredentialStore()

        # Initialize challenge service
        self._challenge_service = challenge_service or ChallengeService()

    def generate_registration_options(
        self,
        user_id: Any,
        username: str,
        display_name: Optional[str] = None,
        rp_id: Optional[str] = None,
    ) -> Dict:
        """
        Generate WebAuthn registration options.

        Args:
            user_id: User's ID
            username: User's username (typically email)
            display_name: User's display name (defaults to username)
            rp_id: Optional RP_ID override for this request. When None, falls
                back to the configured RP_ID. Use this to serve multiple origins
                from a single backend (see ``PasskeyConfiguration.resolve_rp_id``).

        Returns:
            Registration options dict to send to frontend

        Raises:
            MaxCredentialsReachedError: If user has max credentials
        """
        effective_rp_id = rp_id or self._config.rp_id
        # Check credential limit
        existing_count = self._credential_store.count_by_user(user_id)
        if existing_count >= self._config.max_credentials_per_user:
            raise MaxCredentialsReachedError(
                f"User has reached maximum of {self._config.max_credentials_per_user} credentials"
            )

        # Get existing credentials for exclusion
        existing_credentials = self._credential_store.get_by_user(user_id)
        exclude_credentials = [
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(cred.credential_id),
                type=PublicKeyCredentialType.PUBLIC_KEY,
                transports=self._parse_transports(cred.transports),
            )
            for cred in existing_credentials
        ]

        # Build authenticator selection criteria
        authenticator_selection = self._build_authenticator_selection()

        # Generate user handle for discoverable credentials
        user_handle = generate_user_handle()

        # Generate challenge
        challenge = self._challenge_service.generate(
            challenge_type=ChallengeType.REGISTRATION,
            user_id=user_id,
            metadata={"user_handle": base64url_encode(user_handle)},
        )

        # Build supported algorithms
        pub_key_cred_params = [COSEAlgorithmIdentifier(alg) for alg in self._config.supported_algorithms]

        # Generate options using py-webauthn
        options = generate_registration_options(
            rp_id=effective_rp_id,
            rp_name=self._config.rp_name,
            user_id=user_handle,
            user_name=username,
            user_display_name=display_name or username,
            challenge=base64url_to_bytes(challenge),
            timeout=self._config.registration_timeout,
            attestation=self._get_attestation_preference(),
            authenticator_selection=authenticator_selection,
            exclude_credentials=exclude_credentials if exclude_credentials else None,
            supported_pub_key_algs=pub_key_cred_params,
        )

        # Convert to JSON-serializable dict
        options_json = json.loads(options_to_json(options))

        # Add our challenge (already stored)
        options_json["_challenge"] = challenge
        options_json["_user_id"] = str(user_id)
        options_json["_user_handle"] = base64url_encode(user_handle)

        return options_json

    def verify_registration(
        self,
        credential_data: Dict,
        user_id: Any,
        credential_name: Optional[str] = None,
        expected_rp_id: Optional[str] = None,
    ) -> CredentialData:
        """
        Verify WebAuthn registration response.

        Args:
            credential_data: Registration response from frontend
            user_id: User's ID
            credential_name: Optional name for the credential
            expected_rp_id: Optional RP_ID override. MUST match the ``rp_id``
                used when the options were generated for this challenge. When
                None, falls back to the configured RP_ID.

        Returns:
            Saved credential data

        Raises:
            InvalidCredentialDataError: If credential data is invalid
            SignatureVerificationError: If verification fails
        """
        effective_rp_id = expected_rp_id or self._config.rp_id
        try:
            # Extract required fields
            credential_id = credential_data.get("id") or credential_data.get("rawId")
            response = credential_data.get("response", {})
            client_data_json = response.get("clientDataJSON")
            attestation_object = response.get("attestationObject")
            transports = response.get("transports", [])

            if not all([credential_id, client_data_json, attestation_object]):
                raise InvalidCredentialDataError("Missing required credential fields")

            # Parse client data to get challenge
            client_data_bytes = base64url_to_bytes(client_data_json)
            client_data = json.loads(client_data_bytes.decode("utf-8"))
            challenge = client_data.get("challenge")

            if not challenge:
                raise InvalidCredentialDataError("Challenge not found in client data")

            # Validate challenge and get metadata
            self._challenge_service.validate(
                challenge=challenge,
                expected_type=ChallengeType.REGISTRATION,
                user_id=user_id,
                consume=True,
            )

            # Get user handle from challenge metadata
            challenge_data = self._challenge_service.get_challenge_data(challenge)
            user_handle = challenge_data.get("metadata", {}).get("user_handle", "") if challenge_data else ""

            # Validate origin
            origin = client_data.get("origin")
            if origin not in self._config.allowed_origins:
                raise InvalidOriginError(f"Origin '{origin}' not in allowed origins")

            # Build clean credential structure for py-webauthn (remove non-standard fields like 'name')
            # py-webauthn 2.x expects camelCase field names when passing as dict/JSON
            # Note: id and rawId contain the same credential ID - id is base64url string from browser,
            # rawId is our base64url encoding of the ArrayBuffer. Use id as fallback if rawId missing.
            cred_id = credential_data.get("id")
            raw_id = credential_data.get("rawId") or cred_id  # Fallback to id if rawId not provided

            if not raw_id:
                raise InvalidCredentialDataError("Credential missing required rawId")

            webauthn_credential = {
                "id": cred_id,
                "rawId": raw_id,  # camelCase for py-webauthn 2.x
                "type": credential_data.get("type", "public-key"),
                "response": {
                    "clientDataJSON": client_data_json,  # camelCase
                    "attestationObject": attestation_object,  # camelCase
                },
            }

            # Add optional fields if available (camelCase)
            if credential_data.get("authenticatorAttachment"):
                webauthn_credential["authenticatorAttachment"] = credential_data.get("authenticatorAttachment")

            if credential_data.get("clientExtensionResults"):
                webauthn_credential["clientExtensionResults"] = credential_data.get("clientExtensionResults")

            # Add transports to response if available
            if transports:
                webauthn_credential["response"]["transports"] = transports

            # Verify registration using py-webauthn
            verification = verify_registration_response(
                credential=webauthn_credential,
                expected_challenge=base64url_to_bytes(challenge),
                expected_rp_id=effective_rp_id,
                expected_origin=self._config.allowed_origins,
                require_user_verification=self._config.user_verification == "required",
            )

            # Extract credential data from verification
            cred_id_b64 = bytes_to_base64url(verification.credential_id)
            public_key_b64 = bytes_to_base64url(verification.credential_public_key)
            aaguid_str = format_aaguid(verification.aaguid) if verification.aaguid else ""

            # =========================================================================
            # Authenticator Attachment Detection (per WebAuthn Level 3 spec)
            # https://www.w3.org/TR/webauthn-3/#authenticator-attachment-modality
            # =========================================================================
            # Priority order:
            # 1. Direct from credential response (most reliable - browser provides this)
            # 2. Infer from transports array
            # 3. Empty = unknown (valid per spec, don't assume)
            authenticator_attachment = ""

            # Check direct authenticatorAttachment from credential (browser-provided)
            cred_attachment = credential_data.get("authenticatorAttachment")
            if cred_attachment in ("platform", "cross-platform"):
                authenticator_attachment = cred_attachment
            elif transports:
                # Infer from transports per WebAuthn spec:
                # - 'internal': Platform authenticator (TouchID, FaceID, Windows Hello)
                # - 'hybrid': Cross-device (phone as authenticator via QR/BLE)
                # - 'usb', 'nfc', 'ble': Cross-platform security keys
                # Note: Empty transports = all supported (per spec), treat as unknown
                if "internal" in transports:
                    authenticator_attachment = AuthenticatorAttachment.PLATFORM.value
                elif any(t in transports for t in ["hybrid", "usb", "nfc", "ble"]):
                    authenticator_attachment = AuthenticatorAttachment.CROSS_PLATFORM.value

            # =========================================================================
            # Backup Eligibility & State (BE/BS flags per WebAuthn Level 3)
            # https://w3c.github.io/webauthn/#sctn-credential-backup
            # =========================================================================
            # BE (Backup Eligible) = credential_device_type:
            #   - MULTI_DEVICE: Can be synced (iCloud Keychain, Google Password Manager, 1Password)
            #   - SINGLE_DEVICE: Device-bound, cannot be synced (hardware security keys)
            #
            # BS (Backup State) = credential_backed_up:
            #   - True: Credential IS currently synced to cloud
            #   - False: Not yet synced OR device-bound
            is_backup_eligible = False
            is_backup_state = False

            # Check credential_device_type for backup eligibility
            if hasattr(verification, "credential_device_type"):
                device_type = verification.credential_device_type
                # Compare against enum value - MULTI_DEVICE means cloud-syncable
                is_backup_eligible = (
                    str(device_type) == "multi_device" or getattr(device_type, "value", None) == "multi_device"
                )

            # Check credential_backed_up for current backup state
            if hasattr(verification, "credential_backed_up"):
                is_backup_state = bool(verification.credential_backed_up)

            # Create credential data
            credential = CredentialData(
                id="",  # Will be generated by storage
                user_id=user_id,
                credential_id=cred_id_b64,
                public_key=public_key_b64,
                algorithm=-7,  # ES256 (ECDSA with P-256 and SHA-256) - most common for passkeys
                sign_count=verification.sign_count,
                aaguid=aaguid_str,
                name=credential_name or "",
                transports=transports,
                authenticator_attachment=authenticator_attachment,
                backup_eligible=is_backup_eligible,
                backup_state=is_backup_state,
                is_discoverable=self._config.resident_key in ["required", "preferred"],
                user_handle=user_handle,
                attestation_object=attestation_object,
            )

            # Save credential
            saved_credential = self._credential_store.save(credential)

            return saved_credential

        except (KeyError, ValueError, TypeError) as e:
            raise InvalidCredentialDataError(f"Invalid credential data: {str(e)}")
        except Exception as e:
            if isinstance(e, (InvalidCredentialDataError, InvalidOriginError)):
                raise
            raise SignatureVerificationError(f"Registration verification failed: {str(e)}")

    def generate_authentication_options(
        self,
        user_id: Optional[Any] = None,
        username: Optional[str] = None,
        rp_id: Optional[str] = None,
    ) -> Dict:
        """
        Generate WebAuthn authentication options.

        Args:
            user_id: Optional user ID (for non-discoverable credentials)
            username: Optional username to look up user
            rp_id: Optional RP_ID override for this request. When None, falls
                back to the configured RP_ID.

        Returns:
            Authentication options dict to send to frontend
        """
        effective_rp_id = rp_id or self._config.rp_id
        allow_credentials = []

        # If user specified, get their credentials
        if user_id:
            credentials = self._credential_store.get_by_user(user_id)
            allow_credentials = [
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(cred.credential_id),
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    transports=self._parse_transports(cred.transports),
                )
                for cred in credentials
            ]

        # Generate challenge
        challenge = self._challenge_service.generate(
            challenge_type=ChallengeType.AUTHENTICATION,
            user_id=user_id,
        )

        # Generate options using py-webauthn
        options = generate_authentication_options(
            rp_id=effective_rp_id,
            challenge=base64url_to_bytes(challenge),
            timeout=self._config.authentication_timeout,
            allow_credentials=allow_credentials if allow_credentials else None,
            user_verification=self._get_user_verification_requirement(),
        )

        # Convert to JSON-serializable dict
        options_json = json.loads(options_to_json(options))

        # Add our challenge reference
        options_json["_challenge"] = challenge

        return options_json

    def verify_authentication(
        self,
        credential_data: Dict,
        expected_rp_id: Optional[str] = None,
    ) -> AuthenticationResult:
        """
        Verify WebAuthn authentication response.

        Args:
            credential_data: Authentication response from frontend
            expected_rp_id: Optional RP_ID override. MUST match the ``rp_id``
                used when the options were generated for this challenge. When
                None, falls back to the configured RP_ID.

        Returns:
            Authentication result with user info

        Raises:
            CredentialNotFoundError: If credential not found
            CredentialRevokedError: If credential is revoked
            CounterRegressionError: If counter regression detected
            SignatureVerificationError: If verification fails
        """
        effective_rp_id = expected_rp_id or self._config.rp_id
        try:
            # Extract required fields
            credential_id = credential_data.get("id") or credential_data.get("rawId")
            response = credential_data.get("response", {})
            client_data_json = response.get("clientDataJSON")
            authenticator_data = response.get("authenticatorData")
            signature = response.get("signature")
            user_handle = response.get("userHandle")

            if not all([credential_id, client_data_json, authenticator_data, signature]):
                raise InvalidCredentialDataError("Missing required authentication fields")

            # Get stored credential
            stored_credential = self._credential_store.get_by_credential_id(credential_id)
            if not stored_credential:
                raise CredentialNotFoundError(f"Credential not found: {credential_id[:20]}...")

            if not stored_credential.is_active:
                raise CredentialRevokedError("Credential has been revoked")

            # Parse client data to get challenge
            client_data_bytes = base64url_to_bytes(client_data_json)
            client_data = json.loads(client_data_bytes.decode("utf-8"))
            challenge = client_data.get("challenge")

            if not challenge:
                raise InvalidCredentialDataError("Challenge not found in client data")

            # Validate challenge
            self._challenge_service.validate(
                challenge=challenge,
                expected_type=ChallengeType.AUTHENTICATION,
                consume=True,
            )

            # Validate origin
            origin = client_data.get("origin")
            if origin not in self._config.allowed_origins:
                raise InvalidOriginError(f"Origin '{origin}' not in allowed origins")

            # Build clean credential structure for py-webauthn (remove non-standard fields)
            # py-webauthn 2.x expects camelCase field names when passing as dict/JSON
            # Note: id and rawId contain the same credential ID - use id as fallback if rawId missing
            cred_id = credential_data.get("id")
            raw_id = credential_data.get("rawId") or cred_id  # Fallback to id if rawId not provided

            webauthn_credential = {
                "id": cred_id,
                "rawId": raw_id,  # camelCase for py-webauthn 2.x
                "type": credential_data.get("type", "public-key"),
                "response": {
                    "clientDataJSON": client_data_json,  # camelCase
                    "authenticatorData": authenticator_data,  # camelCase
                    "signature": signature,
                },
            }

            # Add optional fields if available (camelCase)
            if credential_data.get("authenticatorAttachment"):
                webauthn_credential["authenticatorAttachment"] = credential_data.get("authenticatorAttachment")

            if credential_data.get("clientExtensionResults"):
                webauthn_credential["clientExtensionResults"] = credential_data.get("clientExtensionResults")

            # Add userHandle to response if available (camelCase)
            if user_handle:
                webauthn_credential["response"]["userHandle"] = user_handle

            # Verify authentication using py-webauthn
            verification = verify_authentication_response(
                credential=webauthn_credential,
                expected_challenge=base64url_to_bytes(challenge),
                expected_rp_id=effective_rp_id,
                expected_origin=self._config.allowed_origins,
                credential_public_key=base64url_to_bytes(stored_credential.public_key),
                credential_current_sign_count=stored_credential.sign_count,
                require_user_verification=self._config.user_verification == "required",
            )

            # Validate counter if enabled
            if self._config.counter_validation_enabled:
                if verification.new_sign_count <= stored_credential.sign_count:
                    # Counter regression - possible cloned authenticator
                    raise CounterRegressionError(
                        details={
                            "stored_count": stored_credential.sign_count,
                            "received_count": verification.new_sign_count,
                        }
                    )

            # Update counter and last used
            self._credential_store.update_counter(credential_id, verification.new_sign_count)
            self._credential_store.update_last_used(credential_id)

            return AuthenticationResult(
                user_id=stored_credential.user_id,
                credential_id=credential_id,
                sign_count=verification.new_sign_count,
                user_verified=verification.user_verified if hasattr(verification, "user_verified") else True,
                backup_eligible=stored_credential.backup_eligible,
                backup_state=stored_credential.backup_state,
            )

        except (KeyError, ValueError, TypeError) as e:
            raise InvalidCredentialDataError(f"Invalid authentication data: {str(e)}")
        except Exception as e:
            if isinstance(
                e,
                (
                    InvalidCredentialDataError,
                    InvalidOriginError,
                    CredentialNotFoundError,
                    CredentialRevokedError,
                    CounterRegressionError,
                ),
            ):
                raise
            raise SignatureVerificationError(f"Authentication verification failed: {str(e)}")

    def get_credentials_for_user(self, user_id: Any) -> List[CredentialData]:
        """Get all credentials for a user"""
        return self._credential_store.get_by_user(user_id)

    def revoke_credential(self, credential_id: str, reason: str = "") -> None:
        """Revoke a credential"""
        self._credential_store.revoke(credential_id, reason)

    def delete_credential(self, credential_id: str) -> bool:
        """Delete a credential"""
        return self._credential_store.delete(credential_id)

    def update_credential_name(self, credential_id: str, name: str) -> None:
        """Update credential name"""
        self._credential_store.update_name(credential_id, name)

    # Helper methods

    def _build_authenticator_selection(self) -> AuthenticatorSelectionCriteria:
        """Build authenticator selection criteria from config"""
        attachment = None
        if self._config.authenticator_attachment:
            attachment = WebAuthnAuthenticatorAttachment(self._config.authenticator_attachment)

        resident_key = WebAuthnResidentKeyRequirement(self._config.resident_key)
        user_verification = WebAuthnUserVerificationRequirement(self._config.user_verification)

        return AuthenticatorSelectionCriteria(
            authenticator_attachment=attachment,
            resident_key=resident_key,
            user_verification=user_verification,
        )

    def _get_attestation_preference(self) -> AttestationConveyancePreference:
        """Get attestation preference from config"""
        return AttestationConveyancePreference(self._config.attestation)

    def _get_user_verification_requirement(self) -> WebAuthnUserVerificationRequirement:
        """Get user verification requirement from config"""
        return WebAuthnUserVerificationRequirement(self._config.user_verification)

    def _parse_transports(self, transports: List[str]) -> List[WebAuthnAuthenticatorTransport]:
        """Parse transport strings to WebAuthn transport enums"""
        result = []
        for t in transports:
            try:
                result.append(WebAuthnAuthenticatorTransport(t))
            except ValueError:
                # Unknown transport, skip
                pass
        return result
