from transformers import pipeline


def analyze_security_report(report_text):
    """
    Takes raw report text or combined scan results and generates
    an intelligent summary or missing parts analysis.
    """

    summarizer = pipeline("text2text-generation",model="google-/flan-t5-base")

    prompt=f"""
    Analyze this web security scan report and identify:
    - Missing security controls or untested areas
    - Potential improvements
    - Risk summary in short

    Report:
    {report_text}

    """

    result = summarizer(prompt,max_length=200,do_sample=False)
    return result[0]['generated_text']

if __name__=="__main__":
    sample_report = """
    Target: example.com
    Open ports: 80, 443
    Server: Apache/2.4.41
    Missing headers: X-Frame-Options, Content-Security-Policy
    """
    print(analyze_security_report)

