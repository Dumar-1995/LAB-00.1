import dns.resolver


def print_separator(title):
    print("=" * 60)
    print(title)
    print("=" * 60)


def get_dns_records(domain, record_type):
    """
    Obtains DNS records for a specific record type.
    """

    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(record) for record in answers]

    except dns.resolver.NoAnswer:
        return []

    except dns.resolver.NXDOMAIN:
        print(f"\n[-] Domain does not exist: {domain}")
        return []

    except dns.resolver.Timeout:
        print(f"\n[-] DNS query timed out for {record_type}")
        return []

    except dns.resolver.NoNameservers:
        print(f"\n[-] No DNS nameservers available for {record_type}")
        return []

    except Exception as error:
        print(f"\n[-] Error checking {record_type}: {error}")
        return []


def analyze_spf(txt_records):
    """
    Searches for and analyzes the SPF record.
    """

    spf_record = None

    for record in txt_records:
        clean_record = record.strip('"')

        if clean_record.lower().startswith("v=spf1"):
            spf_record = clean_record
            break

    if not spf_record:
        return {
            "found": False,
            "record": None,
            "policy": "NOT FOUND",
            "score": 0,
            "max_score": 40,
            "assessment": "No SPF protection detected."
        }

    spf_lower = spf_record.lower()

    if "-all" in spf_lower:
        policy = "STRICT FAIL (-all)"
        score = 40
        assessment = (
            "Strong SPF policy. Unauthorized senders should fail SPF."
        )

    elif "~all" in spf_lower:
        policy = "SOFT FAIL (~all)"
        score = 25
        assessment = (
            "Moderate SPF policy. Unauthorized senders may still be accepted "
            "depending on the receiving server."
        )

    elif "?all" in spf_lower:
        policy = "NEUTRAL (?all)"
        score = 10
        assessment = (
            "Weak SPF policy. Unauthorized senders are not clearly rejected."
        )

    elif "+all" in spf_lower:
        policy = "PERMISSIVE (+all)"
        score = 0
        assessment = (
            "Very weak SPF policy. Any server is authorized to send email."
        )

    else:
        policy = "POLICY NOT CLEAR"
        score = 15
        assessment = (
            "SPF record detected, but the final policy could not be clearly "
            "classified."
        )

    return {
        "found": True,
        "record": spf_record,
        "policy": policy,
        "score": score,
        "max_score": 40,
        "assessment": assessment
    }


def get_dmarc_record(domain):
    """
    Queries the DMARC record from _dmarc.domain.
    """

    dmarc_domain = f"_dmarc.{domain}"

    try:
        answers = dns.resolver.resolve(dmarc_domain, "TXT")

        for record in answers:
            clean_record = str(record).strip('"')

            if clean_record.lower().startswith("v=dmarc1"):
                return clean_record

        return None

    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.Timeout,
        dns.resolver.NoNameservers
    ):
        return None

    except Exception:
        return None


def analyze_dmarc(dmarc_record):
    """
    Analyzes the DMARC policy.
    """

    if not dmarc_record:
        return {
            "found": False,
            "record": None,
            "policy": "NOT FOUND",
            "score": 0,
            "max_score": 60,
            "assessment": "No DMARC protection detected."
        }

    dmarc_lower = dmarc_record.lower()

    if "p=reject" in dmarc_lower:
        policy = "REJECT"
        score = 60
        assessment = (
            "Strong DMARC policy. Failing messages should be rejected."
        )

    elif "p=quarantine" in dmarc_lower:
        policy = "QUARANTINE"
        score = 45
        assessment = (
            "Good DMARC policy. Failing messages should be sent to quarantine."
        )

    elif "p=none" in dmarc_lower:
        policy = "NONE"
        score = 20
        assessment = (
            "Monitoring mode only. Failing messages are not actively enforced."
        )

    else:
        policy = "POLICY NOT CLEAR"
        score = 10
        assessment = (
            "DMARC record detected, but the enforcement policy is unclear."
        )

    return {
        "found": True,
        "record": dmarc_record,
        "policy": policy,
        "score": score,
        "max_score": 60,
        "assessment": assessment
    }


def calculate_risk_level(score):
    """
    Calculates the email security risk level.
    """

    if score >= 85:
        return "LOW"

    elif score >= 60:
        return "MEDIUM"

    else:
        return "HIGH"


def print_recommendations(spf_analysis, dmarc_analysis):
    """
    Prints security recommendations based on the analysis.
    """

    recommendations = []

    if not spf_analysis["found"]:
        recommendations.append(
            "Implement an SPF record to define authorized email servers."
        )

    elif spf_analysis["policy"] == "SOFT FAIL (~all)":
        recommendations.append(
            "Consider reviewing SPF and migrating from ~all to -all "
            "when all legitimate senders are properly identified."
        )

    elif spf_analysis["policy"] in [
        "NEUTRAL (?all)",
        "PERMISSIVE (+all)"
    ]:
        recommendations.append(
            "Strengthen the SPF policy by restricting unauthorized senders."
        )

    if not dmarc_analysis["found"]:
        recommendations.append(
            "Implement DMARC to protect against email spoofing."
        )

    elif dmarc_analysis["policy"] == "NONE":
        recommendations.append(
            "Consider migrating DMARC from p=none to p=quarantine "
            "after reviewing DMARC reports."
        )

    elif dmarc_analysis["policy"] == "QUARANTINE":
        recommendations.append(
            "Consider migrating DMARC from p=quarantine to p=reject "
            "when legitimate email sources are fully validated."
        )

    print_separator("SECURITY RECOMMENDATIONS")

    if recommendations:

        for recommendation in recommendations:
            print(f"\n- {recommendation}")

    else:
        print("\n[+] No major recommendations detected.")


def main():

    print_separator("DNS EMAIL SECURITY ANALYZER")

    domain = input(
        "\nEnter a domain (example.com): "
    ).strip()

    if not domain:
        print("\n[-] No domain entered.")
        return

    print(f"\n[+] Target domain: {domain}")

    print_separator("DNS RECORDS INFORMATION")

    record_types = {
        "A": "Maps a domain name to an IPv4 address.",
        "AAAA": "Maps a domain name to an IPv6 address.",
        "MX": "Mail servers responsible for receiving email.",
        "NS": "Authoritative DNS nameservers for the domain.",
        "TXT": "Stores text information and email security policies."
    }

    all_records = {}

    for record_type, description in record_types.items():

        print_separator(f"{record_type} RECORDS")

        print(f"\nDescription: {description}\n")

        records = get_dns_records(domain, record_type)

        all_records[record_type] = records

        if records:

            print(f"[+] {len(records)} record(s) found:\n")

            for record in records:
                print(f"  - {record}")

        else:
            print("[-] No records found.")

    # SPF ANALYSIS

    print_separator("SPF ANALYSIS")

    spf_analysis = analyze_spf(
        all_records.get("TXT", [])
    )

    if spf_analysis["found"]:

        print("\n[+] SPF record detected:\n")
        print(f"  {spf_analysis['record']}\n")

        print(f"Policy: {spf_analysis['policy']}")
        print(
            f"Score: {spf_analysis['score']}/"
            f"{spf_analysis['max_score']}"
        )
        print(f"Assessment: {spf_analysis['assessment']}")

    else:

        print("\n[-] No SPF record detected.")
        print(
            f"Score: {spf_analysis['score']}/"
            f"{spf_analysis['max_score']}"
        )
        print(f"Assessment: {spf_analysis['assessment']}")

    # DMARC ANALYSIS

    print_separator("DMARC ANALYSIS")

    dmarc_domain = f"_dmarc.{domain}"

    print(f"\nChecking: {dmarc_domain}")

    dmarc_record = get_dmarc_record(domain)

    dmarc_analysis = analyze_dmarc(dmarc_record)

    if dmarc_analysis["found"]:

        print("\n[+] DMARC record detected:\n")
        print(f"  {dmarc_analysis['record']}\n")

        print(f"Policy: {dmarc_analysis['policy']}")
        print(
            f"Score: {dmarc_analysis['score']}/"
            f"{dmarc_analysis['max_score']}"
        )
        print(f"Assessment: {dmarc_analysis['assessment']}")

    else:

        print("\n[-] No DMARC record detected.")
        print(
            f"Score: {dmarc_analysis['score']}/"
            f"{dmarc_analysis['max_score']}"
        )
        print(f"Assessment: {dmarc_analysis['assessment']}")

    # EMAIL SECURITY SCORE

    total_score = (
        spf_analysis["score"] +
        dmarc_analysis["score"]
    )

    risk_level = calculate_risk_level(total_score)

    print_separator("DNS EMAIL SECURITY SCORE")

    print(
        f"\nSPF Security: "
        f"{spf_analysis['score']}/{spf_analysis['max_score']}"
    )

    print(
        f"DMARC Security: "
        f"{dmarc_analysis['score']}/{dmarc_analysis['max_score']}"
    )

    print("\n" + "-" * 60)

    print(f"\nEMAIL SECURITY SCORE: {total_score}/100")
    print(f"RISK LEVEL: {risk_level}")

    if risk_level == "LOW":
        print("\nAssessment: STRONG EMAIL SECURITY CONFIGURATION")

    elif risk_level == "MEDIUM":
        print("\nAssessment: MODERATE EMAIL SECURITY CONFIGURATION")

    else:
        print("\nAssessment: WEAK EMAIL SECURITY CONFIGURATION")

    # RECOMMENDATIONS

    print_recommendations(
        spf_analysis,
        dmarc_analysis
    )

    print_separator("DNS SECURITY ANALYSIS COMPLETED")


if __name__ == "__main__":
    main()
