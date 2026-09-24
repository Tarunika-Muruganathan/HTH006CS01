import json
import os
from google import genai
from google.genai import types

def analyze_customer_dataset(dataset_content: str, api_key: str = None) -> str:
    """
    Analyzes a customer dataset with strict guardrails to only respond to the logs
    and ignore any other data.
    """
    key = api_key or os.environ.get("GEMINI_API_KEY")
    client = genai.Client(api_key=key)

    prompt = f"""
    You are a strictly guardrailed Data Analysis AI.
    Your task is to analyze the following dataset provided by a customer and generate a comprehensive security and anomaly report.
    
    STRICT GUARDRAILS & INSTRUCTIONS:
    1. You MUST ONLY respond based on the data provided in the dataset below.
    2. Do NOT hallucinate or incorporate outside knowledge about users, events, or external data sources.
    3. The dataset is strictly isolated. Do NOT reference any other users, logs, or existing baseline data.
    4. If the dataset does not contain enough information to make a conclusion, state that clearly.
    5. Format the output as a detailed Markdown report.

    --- CUSTOMER DATASET ---
    {dataset_content}
    --- END OF CUSTOMER DATASET ---
    """
    
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
    )
    return response.text
