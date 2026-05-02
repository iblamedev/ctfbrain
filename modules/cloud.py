import re
from core.colors import red, green, yellow, highlight
from core.executor import run_cmd
from core.tools import check_tool, requires_tools

FLAG_PATTERN = r'[a-zA-Z0-9_]+\{[^}]*\}'

def extract_flag_from_output(output):
    """Extract flag from command output"""
    if not output:
        return None
    flags = re.findall(FLAG_PATTERN, str(output))
    if flags:
        return flags[0]
    return None

@requires_tools('aws', 's3scanner')
def run_cloud(target):
    """Run cloud recon and return flag if found"""
    print(f"{green('[+]')} Running Cloud Recon on: {target}")

    if "s3" in target and "amazonaws.com" in target:
        print(f"{green('[+]')} AWS S3 Bucket detected.")
        
        bucket_name = target.split("//")[-1].split(".")[0]

        if check_tool("aws"):
            print(f"{green('[+]')} Attempting AWS CLI listing (No Sign Request)...")
            result = run_cmd(f"aws s3 ls s3://{bucket_name} --no-sign-request")
            flag = extract_flag_from_output(result)
            if flag:
                return flag
        
        if check_tool("s3scanner"):
            print(f"{green('[+]')} Running s3scanner...")
            result = run_cmd(f"s3scanner scan --bucket {target}")
            flag = extract_flag_from_output(result)
            if flag:
                return flag

    else:
        print(f"{yellow('[*]')} Generic Cloud Target.")
        print("    If this is an IP, run the Network module.")
        print("    If this is a domain, run the Web module.")

    print(f"\n{green('[+]')} Cloud analysis complete - no flag found.")
    return None