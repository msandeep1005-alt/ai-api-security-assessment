import os

from dotenv import load_dotenv
from google import genai


load_dotenv(".env", override=True)


def get_gemini_client() -> genai.Client:
    """
    Create and return a Gemini API client using the
    local environment configuration.
    """

    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is not configured. "
            "Set it in the project's .env file."
        )

    return genai.Client(api_key=api_key)


def get_model_name() -> str:
    """
    Return the Gemini model used by the application.
    """

    return os.getenv(
        "GEMINI_MODEL",
        "gemini-2.5-flash",
    )
