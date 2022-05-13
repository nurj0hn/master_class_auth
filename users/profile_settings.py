PROFILE_UPLOAD_DIR = 'users/profile'
HOST_OF_SERVER = 'http://localhost:8000'


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
