import time

class Limiter:
    def __init__(self, limit_per_minute, limit_per_hour, limit_per_day):
        self.limit_per_minute = limit_per_minute
        self.limit_per_hour = limit_per_hour
        self.limit_per_day = limit_per_day
        self.tokens_minute = self.limit_per_minute
        self.tokens_hour = self.limit_per_hour
        self.tokens_day = self.limit_per_day
        self.last_update_minute = int(time.time())
        self.last_update_hour = int(time.time())
        self.last_update_day = int(time.time())

    def _update_tokens(self):
        current_time = int(time.time())

        # Update tokens for each time period
        elapsed_minutes = current_time - self.last_update_minute
        elapsed_hours = current_time - self.last_update_hour
        elapsed_days = current_time - self.last_update_day

        # Refill tokens based on elapsed time
        self.tokens_minute = min(
            self.limit_per_minute,
            self.tokens_minute + (elapsed_minutes * (self.limit_per_minute // 60))
        )
        self.tokens_hour = min(
            self.limit_per_hour,
            self.tokens_hour + (elapsed_hours * (self.limit_per_hour // 3600))
        )
        self.tokens_day = min(
            self.limit_per_day,
            self.tokens_day + (elapsed_days * (self.limit_per_day // 86400))
        )

        self.last_update_minute = current_time
        self.last_update_hour = current_time
        self.last_update_day = current_time

    def can_submit(self):
        self._update_tokens()
        return all([
            self.tokens_minute > 0,
            self.tokens_hour > 0,
            self.tokens_day > 0
        ])

    def submit(self):
        if self.can_submit():
            self.tokens_minute -= 1
            self.tokens_hour -= 1
            self.tokens_day -= 1
            return True
        return False