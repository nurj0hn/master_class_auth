PROFILE_UPLOAD_DIR = 'users/profile'
HOST_OF_SERVER = 'http://164.92.190.147:8003'


class UserType:
    PLAYER = 'player'
    REFEREE = 'referee'
    MANAGER = 'manager'

    @classmethod
    def choices(cls):
        return (
            (cls.MANAGER, cls.MANAGER),
            (cls.PLAYER, cls.PLAYER),
            (cls.REFEREE, cls.REFEREE),
        )
