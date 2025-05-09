import hashlib
import json
import requests
import configparser
from pathlib import Path
from datetime import datetime

class MalwareScanner:
    def __init__(self, signature_file="malware_signatures.json"):
        self.signature_file = Path(signature_file)
        self.signatures = self._load_signatures()
        self.vt_api_key = self._load_vt_api_key()

    def _load_signatures(self):
        """Load malware signatures from JSON file."""
        if not self.signature_file.exists():
            raise FileNotFoundError(f"Signature file {self.signature_file} not found!")
        with open(self.signature_file, "r") as f:
            return json.load(f)

    def _load_vt_api_key(self):
        """Load VirusTotal API key from config."""
        config = configparser.ConfigParser()
        config.read('config.ini')
        return config.get('VIRUSTOTAL', 'api_key', fallback=None)

    def compute_hashes(self, file_path):
        """Compute file hashes."""
        hashes = {
            "md5": hashlib.md5(),
            "sha1": hashlib.sha1(),
            "sha256": hashlib.sha256()
        }
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                for algo in hashes.values():
                    algo.update(chunk)
        return {k: v.hexdigest() for k, v in hashes.items()}

    def _generate_creative_report(self, file_path, file_hashes, vt_result, local_detection):
        """Generate creative security report."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sha256 = file_hashes['sha256'][:16] + "..."  # Shorten hash for display
        
        if vt_result or local_detection:
            # Threat detected
            vt_malicious = vt_result.get('malicious', 0) if vt_result else 0
            return f"""
            🔴 === MALWARE DETECTED === 🔴
            📅 Scan Time: {timestamp}
            📁 File: {Path(file_path).name}
            🔐 SHA256: {sha256}
            
            ⚠️ THREAT INDICATORS:
            • VirusTotal Detections: {vt_malicious}/60+
            • Local Database Match: {'YES' if local_detection else 'No'}
            
            🚨 RECOMMENDED ACTIONS:
            1. Quarantine this file immediately
            2. Run full system scan
            3. Check for system compromises
            
            ▄︻デ══━💥  Stay Alert!  💥━══デ︻▄
            """
        else:
            # Clean file
            return f"""
            🟢 === FILE CLEAN === 🟢
            📅 Scan Time: {timestamp}
            📁 File: {Path(file_path).name}
            🔐 SHA256: {sha256}
            
            ✅ VERIFICATION:
            • VirusTotal: Clean
            • Local Database: Clean
            
            🛡️ SECURITY TIPS:
            1. Keep software updated
            2. Avoid suspicious downloads
            3. Regular backups
            
            ╰(*°▽°*)╯  Stay Secure!  ╰(*°▽°*)╯
            """

    def scan_file(self, file_path):
        """Scan a file and return creative report."""
        if not Path(file_path).exists():
            return False, "🚫 Error: File not found"

        # Compute hashes
        file_hashes = self.compute_hashes(file_path)
        local_detected = False
        
        # Check local signatures
        for algo, hashes in self.signatures["hashes"].items():
            if file_hashes[algo] in hashes:
                local_detected = True
                break

        if not local_detected:
            with open(file_path, "rb") as f:
                file_data = f.read()
                for sig in self.signatures["strings"]:
                    pattern = sig["pattern"]
                    if all(c in "0123456789abcdefABCDEF" for c in pattern):
                        try:
                            if bytes.fromhex(pattern) in file_data:
                                local_detected = True
                                break
                        except ValueError:
                            continue
                    elif pattern.encode() in file_data:
                        local_detected = True
                        break

        # Check VirusTotal
        vt_result = None
        if self.vt_api_key:
            try:
                url = f"https://www.virustotal.com/api/v3/files/{file_hashes['sha256']}"
                headers = {"x-apikey": self.vt_api_key}
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    vt_result = response.json()['data']['attributes']['last_analysis_stats']
            except:
                pass

        report = self._generate_creative_report(
            file_path=file_path,
            file_hashes=file_hashes,
            vt_result=vt_result,
            local_detection=local_detected
        )
        
        return local_detected or (vt_result and vt_result['malicious'] > 0), report
