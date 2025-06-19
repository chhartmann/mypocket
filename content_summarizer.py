import requests
from bs4 import BeautifulSoup
from PyPDF2 import PdfReader
from io import BytesIO
from langchain_litellm import ChatLiteLLM
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough
import os
from typing import Union
import re

class ContentSummarizer:
    def __init__(self, openrouter_api_key: str):
        """
        Initialize the ContentSummarizer with OpenRouter API key.
        
        Args:
            openrouter_api_key (str): Your OpenRouter API key
        """
        os.environ["OPENROUTER_API_KEY"] = openrouter_api_key
        self.llm = ChatLiteLLM(
            model="openrouter/mistralai/mistral-7b-instruct",
            openrouter_api_key=openrouter_api_key,
            temperature=0.3,
            max_tokens=2000,
            top_p=0.95
        )
        
        self.summary_template = """
        <s>[INST] You are a helpful AI assistant. Please provide a detailed summary of the following text. 
        Focus on capturing all important points and maintain a coherent narrative. 
        The summary should be comprehensive while remaining clear and well-structured.
        
        Text to summarize:
        {content}
        
        Please provide a detailed summary: [/INST]</s>
        """
        
        self.prompt = PromptTemplate(
            template=self.summary_template,
            input_variables=["content"]
        )
        
        # Create a chain using the new LCEL (LangChain Expression Language) syntax
        self.chain = (
            {"content": RunnablePassthrough()}
            | self.prompt
            | self.llm
            | StrOutputParser()
        )

    def _extract_text_from_url(self, url: str) -> str:
        """
        Extract text content from a URL (website or PDF).
        
        Args:
            url (str): The URL to fetch content from
            
        Returns:
            str: Extracted text content
        """
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        content_type = response.headers.get('content-type', '').lower()
        
        if 'application/pdf' in content_type:
            return self._extract_text_from_pdf(response.content)
        else:
            return self._extract_text_from_webpage(response.text)

    def _extract_text_from_pdf(self, pdf_content: bytes) -> str:
        """
        Extract text from PDF content.
        
        Args:
            pdf_content (bytes): PDF file content
            
        Returns:
            str: Extracted text
        """
        pdf_file = BytesIO(pdf_content)
        pdf_reader = PdfReader(pdf_file)
        text = ""
        for page in pdf_reader.pages:
            text += page.extract_text() + "\n"
        return text

    def _extract_text_from_webpage(self, html_content: str) -> str:
        """
        Extract text from HTML content.
        
        Args:
            html_content (str): HTML content
            
        Returns:
            str: Extracted text
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Remove script, style, and other non-content elements
        for element in soup(["script", "style", "nav", "footer", "header", "aside"]):
            element.decompose()
            
        # Get text
        text = soup.get_text()
        
        # Break into lines and remove leading and trailing space on each
        lines = (line.strip() for line in text.splitlines())
        # Break multi-headlines into a line each
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        # Drop blank lines
        text = '\n'.join(chunk for chunk in chunks if chunk)
        
        return text

    def summarize_content(self, url: str) -> str:
        """
        Summarize content from a given URL.
        
        Args:
            url (str): The URL to fetch and summarize content from
            
        Returns:
            str: Summarized content
        """
        try:
            # Extract text from URL
            content = self._extract_text_from_url(url)
            
            # Clean and prepare content
            content = re.sub(r'\s+', ' ', content).strip()
                        
            # Generate summary using LLM
            summary = self.chain.invoke(content)
            
            return summary.strip()
            
        except requests.exceptions.RequestException as e:
            return f"Error fetching content: {str(e)}"
        except Exception as e:
            return f"Error summarizing content: {str(e)}"

# Example usage:
if __name__ == "__main__":
    # Replace with your OpenRouter API key
    OPENROUTER_API_KEY = ""
    
    summarizer = ContentSummarizer(OPENROUTER_API_KEY)
    
    # Example URL
    url = "https://thelearningjourneyebooks.com/wp-content/uploads/2025/04/TheLinuxSecurityJourney_v3_April2025.pdf"
    summary = summarizer.summarize_content(url)
    print(summary) 