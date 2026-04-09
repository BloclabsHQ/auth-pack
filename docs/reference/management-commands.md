# Management Commands

## blockauth_cleanup

Cleans up expired data: stale OTPs, expired WebAuthn challenges, and orphaned credentials.

```bash
python manage.py blockauth_cleanup
```

### What It Cleans

- **Expired OTPs** -- removes OTP records past their validity window
- **Expired challenges** -- removes WebAuthn challenge records that were never completed
- **Stale credentials** -- optionally removes credentials that haven't been used within a configurable period

### Usage

Run periodically (e.g., via cron or Celery beat) to keep the database clean:

```bash
# Cron: daily at 3 AM
0 3 * * * cd /path/to/project && python manage.py blockauth_cleanup
```

```python
# Celery beat
CELERY_BEAT_SCHEDULE = {
    'blockauth-cleanup': {
        'task': 'myapp.tasks.run_blockauth_cleanup',
        'schedule': crontab(hour=3, minute=0),
    },
}
```
