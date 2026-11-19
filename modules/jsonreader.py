import json
import os

FILE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "App.json"
)

def read_app_data():
    try:
        with open(FILE_PATH, "r", encoding="utf-8") as file:
            data = json.load(file)

        if not isinstance(data, dict):
            raise ValueError("JSON root must be an object.")

        required_keys = [
            "version",
            "author",
            "last_updated_at"
        ]

        for key in required_keys:
            if key not in data:
                raise ValueError(f"Missing JSON key: {key}")

        return data

    except FileNotFoundError:
        raise RuntimeError("app.json not found.")

    except json.JSONDecodeError as error:
        raise RuntimeError(f"Invalid JSON: {error}")