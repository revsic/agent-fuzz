from agentfuzz.language.cpp import CppSupports
from agentfuzz.language.supports import LanguageSupports


LANGUAGE_SUPPORT: dict[str, LanguageSupports] = {
    "c/cpp": CppSupports,
}
