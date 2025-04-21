from typing import List

from openai import OpenAI
from rexis.utils.config import settings


class BaseAIProvider:
    """Base class for AI providers."""

    def __init__(self, provider: str):
        """Initialize the BaseAIProvider with the specified provider."""
        self.provider = provider

    def get_embeddings_batch(self, texts: List[str]) -> List[List[float]]:
        """Abstract method to generate embeddings."""
        raise NotImplementedError("Subclasses must implement this method.")
    
    def get_model_query(self, prompt: str) -> str:
        """Abstract method to query the model with a given prompt and return the response."""
        raise NotImplementedError("Subclasses must implement this method.")


class OpenAIProvider(BaseAIProvider):
    """OpenAI implementation of the AIProvider."""
    def __init__(self):
        super().__init__(provider="openai")
        self.embedding_model = settings.models.openai.embedding_model
        self.query_model = settings.models.openai.query_model

        self.client = OpenAI(api_key=settings.models.openai.api_key, base_url=settings.models.openai.base_url)

    def get_embeddings_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate batch embeddings using OpenAI."""
        try:
            response = self.client.embeddings.create(input=texts, model=self.embedding_model)
            return [item.embedding for item in response.data]
        except Exception as e:
            print("OpenAI embedding error:", e)
            raise Exception("Error generating embeddings with OpenAI API.")
        
    def get_model_query(self, prompt: str) -> str:
        """Query the model with a given prompt and return the response."""
        try:
            response = self.client.chat.create(
                model=self.query_model,
                messages=[{"role": "user", "content": prompt}]
            )
            return response["choices"][0]["message"]["content"]
        except Exception as e:
            print("OpenAI query error:", e)
            raise Exception("Error querying OpenAI API.")


class DeepSeekProvider(BaseAIProvider):
    """DeepSeek implementation of the AIProvider."""
    def __init__(self):
        super().__init__(provider="deepseek")
        self.embedding_model = settings.models.deeepseek.embedding_model
        self.query_model = settings.models.deeepseek.query_model

        self.client = OpenAI(api_key=settings.models.deeepseek.api_key, base_url=settings.models.deeepseek.base_url)

    def get_embeddings_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate batch embeddings using DeepSeek."""
        # Implement DeepSeek embedding logic here
        pass
    
    def get_model_query(self, prompt: str) -> str:
        """Query the model with a given prompt and return the response."""
        try:
            response = self.client.chat.completions.create(
                model=self.query_model,
                messages=[
                    {"role": "user", "content": prompt},
                ],
                stream=False
            )
            return response["choices"][0]["message"]["content"]
        except Exception as e:
            print("DeepSeek query error:", e)
            
