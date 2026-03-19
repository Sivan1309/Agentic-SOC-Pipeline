import json
import os
import anthropic

# Initialize Anthropic client
client = anthropic.Anthropic(
    api_key=os.environ.get("REMOVEDEOe--7TEMgYU_NzCJanviTewvM5EM_vdHp32_JmZnXdbXRnaxTLBG1hgcHDOYkuw_6X7GWyHq1L1VaS6gqWiMw-VGQL3gAA")
)

def parse_finding(file_path):
    with open(file_path, 'r') as f:
        finding = json.load(f)
    
    required_fields = ['finding_id', 'type', 'severity', 'description']
    for field in required_fields:
        if field not in finding:
            raise ValueError(f"Missing required field: {field}")
    
    return finding

def build_prompt(finding):
    prompt = f"""You are an expert SOC analyst at a fintech company.
Analyze the following AWS GuardDuty security finding and provide a triage decision.

FINDING DETAILS:
- Finding ID: {finding['finding_id']}
- Type: {finding['type']}
- Severity Score: {finding['severity']}
- Description: {finding['description']}
- Region: {finding.get('region', 'unknown')}
- Account: {finding.get('account_id', 'unknown')}

ACTION DETAILS:
{json.dumps(finding.get('service', {}), indent=2)}

RESOURCE AFFECTED:
{json.dumps(finding.get('resource', {}), indent=2)}

Provide your triage analysis in the following JSON format only.
Do not include any text outside the JSON:

{{
    "finding_id": "{finding['finding_id']}",
    "severity_assessment": "Critical/High/Medium/Low",
    "severity_reasoning": "explain why you assessed this severity",
    "mitre_technique": "T#### - Technique Name",
    "mitre_tactic": "Tactic Name",
    "attack_summary": "brief description of what the attacker is doing",
    "recommended_action": "Contain/Escalate/Dismiss",
    "action_reasoning": "explain why you recommend this action",
    "immediate_steps": [
        "step 1",
        "step 2",
        "step 3"
    ],
    "analyst_notes": "additional context for the SOC team"
}}"""

    return prompt

def call_llm_api(prompt):
    message = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=1000,
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )
    return message.content[0].text

def parse_response(response):
    
    try:
        clean_response = response.strip()
        if "```json" in clean_response:
            clean_response = clean_response.split("```json")[1].split("```")[0].strip()
        elif "```" in clean_response:
            clean_response = clean_response.split("```")[1].split("```")[0].strip()
        
        report = json.loads(clean_response)
        
        return {
            "finding_id": report.get("finding_id", "unknown"),
            "severity_assessment": report.get("severity_assessment", "unknown"),
            "severity_reasoning": report.get("severity_reasoning", "unknown"),
            "mitre_technique": report.get("mitre_technique", "unknown"),
            "mitre_tactic": report.get("mitre_tactic", "unknown"),
            "attack_summary": report.get("attack_summary", "unknown"),
            "recommended_action": report.get("recommended_action", "unknown"),
            "action_reasoning": report.get("action_reasoning", "unknown"),
            "immediate_steps": report.get("immediate_steps", []),
            "analyst_notes": report.get("analyst_notes", "unknown")
        }
    
    except json.JSONDecodeError:
        return {
            "finding_id": "parse_error",
            "severity_assessment": "High",
            "severity_reasoning": "Could not parse LLM response",
            "mitre_technique": "unknown",
            "mitre_tactic": "unknown",
            "attack_summary": "Raw response: " + response,
            "recommended_action": "Escalate",
            "action_reasoning": "Manual review required",
            "immediate_steps": ["Review raw finding manually"],
            "analyst_notes": response
        }

def main():
    import sys
    file_path = sys.argv[1] if len(sys.argv) > 1 else "mock_finding.json"
    
    print(f"\nProcessing finding: {file_path}")
    print("=" * 50)
    
    finding = parse_finding(file_path)
    prompt = build_prompt(finding)
    response = call_llm_api(prompt)
    report = parse_response(response)
    
    print(json.dumps(report, indent=2))
    
    with open("triage_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print("\nReport saved to triage_report.json")

if __name__ == "__main__":
    main()
