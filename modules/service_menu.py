import enum

from Design.menus import render_menu


class ServiceMode(enum.Enum):
    MYSQL  = "mysql"
    FTP    = "ftp"
    HYBRID = "hybrid"


_SERVICE_OPTIONS = [
    "MySQL           (MySQL / MariaDB database server)",
    "FTP             (FTP file transfer server)",
    "Hybrid          (try both MySQL and FTP on the target)",
]

_INDEX_TO_MODE = [
    ServiceMode.MYSQL,
    ServiceMode.FTP,
    ServiceMode.HYBRID,
]


def run_service_menu() -> ServiceMode:
    """Display service mode selection and return the chosen ServiceMode."""
    index = render_menu("SELECT SERVICE", _SERVICE_OPTIONS)
    return _INDEX_TO_MODE[index]
