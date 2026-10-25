import requests


OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.2:1b"


def generate_network_report(metrics, prediction, protocol_stats, top_flows):
    prompt = f"""
You are a cybersecurity assistant integrated into a network traffic analyzer.

Generate a concise natural language report based on the following data.

Basic metrics:
{metrics}

Anomaly detection result:
{prediction}

Protocol statistics:
{protocol_stats}

Top network flows:
{top_flows}

Your report must include:
1. General traffic status.
2. Whether the behavior appears normal or anomalous.
3. Main indicators observed.
4. Recommended next step.

Important:
- Do not claim that an attack is confirmed.
- Say "possible anomaly" or "behavioral deviation" when needed.
- Keep it clear for a non-expert user.
"""

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False
    }

    try:
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=90
        )

        response.raise_for_status()

        data = response.json()

        return data.get("response", "No report generated.")

    except requests.exceptions.ConnectionError:
        return "Ollama is not running. Open Ollama or start the Ollama service."

    except requests.exceptions.Timeout:
        return "The model took too long to respond. Try using a smaller model or a shorter prompt."

    except Exception as error:
        return f"Error generating report: {str(error)}"