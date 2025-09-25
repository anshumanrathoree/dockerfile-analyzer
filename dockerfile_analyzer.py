#!/usr/bin/env python3
"""
Dockerfile Security & Optimization Analyzer
Analyzes Dockerfiles for security issues and optimization opportunities
"""

import re
import os
import sys
import argparse
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class Issue:
    line_num: int
    severity: str  # HIGH, MEDIUM, LOW
    category: str  # SECURITY, OPTIMIZATION, BEST_PRACTICE
    message: str
    line_content: str
    suggestion: Optional[str] = None

class DockerfileAnalyzer:
    def __init__(self):
        self.issues = []
        
    def analyze_file(self, dockerfile_path: str) -> List[Issue]:
        """Analyze a single Dockerfile"""
        self.issues = []
        
        try:
            with open(dockerfile_path, 'r') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Error reading {dockerfile_path}: {e}")
            return []
            
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            self._check_security_issues(line_num, line)
            self._check_optimization_issues(line_num, line)
            self._check_best_practices(line_num, line)
            
        return self.issues
    
    def _check_security_issues(self, line_num: int, line: str):
        """Check for security vulnerabilities"""
        
        # Running as root
        if re.match(r'^USER\s+0\s*$|^USER\s+root\s*$', line, re.IGNORECASE):
            self.issues.append(Issue(
                line_num, "HIGH", "SECURITY",
                "Running as root user is a security risk",
                line,
                "Create a non-root user: RUN adduser --disabled-password --gecos '' appuser && USER appuser"
            ))
        
        # Hardcoded secrets
        secret_patterns = [
            r'password\s*=\s*["\'].*["\']',
            r'api_key\s*=\s*["\'].*["\']',
            r'secret\s*=\s*["\'].*["\']',
            r'token\s*=\s*["\'].*["\']'
        ]
        
        for pattern in secret_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                self.issues.append(Issue(
                    line_num, "HIGH", "SECURITY",
                    "Potential hardcoded secret detected",
                    line,
                    "Use environment variables or secrets management"
                ))
        
        # Using ADD instead of COPY
        if line.upper().startswith('ADD ') and not ('http://' in line or 'https://' in line):
            self.issues.append(Issue(
                line_num, "MEDIUM", "SECURITY",
                "Use COPY instead of ADD for local files",
                line,
                "Replace ADD with COPY for better security"
            ))
        
        # Wget/curl without verification
        if re.search(r'(wget|curl).*http://', line):
            self.issues.append(Issue(
                line_num, "MEDIUM", "SECURITY",
                "Downloading over HTTP without verification",
                line,
                "Use HTTPS and verify checksums"
            ))
    
    def _check_optimization_issues(self, line_num: int, line: str):
        """Check for optimization opportunities"""
        
        # Multiple RUN commands that could be chained
        if line.upper().startswith('RUN '):
            # This is a simplified check - in practice you'd look at consecutive RUN commands
            if 'apt-get update' in line and 'apt-get install' not in line:
                self.issues.append(Issue(
                    line_num, "MEDIUM", "OPTIMIZATION",
                    "apt-get update should be chained with install to reduce layers",
                    line,
                    "Combine: RUN apt-get update && apt-get install -y package"
                ))
        
        # Not cleaning package manager cache
        if 'apt-get install' in line and 'apt-get clean' not in line:
            self.issues.append(Issue(
                line_num, "LOW", "OPTIMIZATION",
                "Package manager cache not cleaned",
                line,
                "Add: && apt-get clean && rm -rf /var/lib/apt/lists/*"
            ))
        
        # Installing unnecessary packages
        unnecessary_packages = ['vim', 'nano', 'curl', 'wget']
        for pkg in unnecessary_packages:
            if f' {pkg} ' in line or f' {pkg}$' in line:
                self.issues.append(Issue(
                    line_num, "LOW", "OPTIMIZATION",
                    f"Potentially unnecessary package: {pkg}",
                    line,
                    "Remove if not required for application runtime"
                ))
    
    def _check_best_practices(self, line_num: int, line: str):
        """Check for Docker best practices"""
        
        # No HEALTHCHECK defined (would need to check entire file)
        # This is simplified - you'd track this across the whole file
        
        # Using latest tag
        if re.search(r'FROM\s+\w+:latest', line):
            self.issues.append(Issue(
                line_num, "MEDIUM", "BEST_PRACTICE",
                "Using 'latest' tag is not recommended",
                line,
                "Use specific version tags for reproducibility"
            ))
        
        # WORKDIR not set
        if line.upper().startswith('COPY ') or line.upper().startswith('ADD '):
            if '/' not in line.split()[-1]:  # Simplified check
                self.issues.append(Issue(
                    line_num, "LOW", "BEST_PRACTICE",
                    "Consider setting WORKDIR before COPY/ADD",
                    line,
                    "Set WORKDIR to define working directory"
                ))
        
        # Expose common insecure ports
        insecure_ports = ['22', '23', '80']
        if line.upper().startswith('EXPOSE '):
            for port in insecure_ports:
                if port in line:
                    self.issues.append(Issue(
                        line_num, "LOW", "BEST_PRACTICE",
                        f"Exposing potentially insecure port: {port}",
                        line,
                        "Consider if this port exposure is necessary"
                    ))

def generate_report(issues: List[Issue], dockerfile_path: str):
    """Generate analysis report"""
    
    if not issues:
        print(f"✅ {dockerfile_path}: No issues found!")
        return
    
    print(f"\n🔍 Analysis Report for {dockerfile_path}")
    print("=" * 50)
    
    # Group by severity
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    category_counts = {"SECURITY": 0, "OPTIMIZATION": 0, "BEST_PRACTICE": 0}
    
    for issue in issues:
        severity_counts[issue.severity] += 1
        category_counts[issue.category] += 1
    
    print(f"📊 Summary: {len(issues)} issues found")
    print(f"   🔴 High: {severity_counts['HIGH']}")
    print(f"   🟡 Medium: {severity_counts['MEDIUM']}")
    print(f"   🔵 Low: {severity_counts['LOW']}")
    print()
    print(f"   🛡️  Security: {category_counts['SECURITY']}")
    print(f"   ⚡ Optimization: {category_counts['OPTIMIZATION']}")
    print(f"   📋 Best Practice: {category_counts['BEST_PRACTICE']}")
    print()
    
    # Sort by severity and line number
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    sorted_issues = sorted(issues, key=lambda x: (severity_order[x.severity], x.line_num))
    
    for issue in sorted_issues:
        severity_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}
        category_icon = {"SECURITY": "🛡️", "OPTIMIZATION": "⚡", "BEST_PRACTICE": "📋"}
        
        print(f"{severity_icon[issue.severity]} Line {issue.line_num}: {category_icon[issue.category]} {issue.message}")
        print(f"   Code: {issue.line_content}")
        if issue.suggestion:
            print(f"   💡 Suggestion: {issue.suggestion}")
        print()

def create_sample_dockerfile():
    """Create a sample Dockerfile with various issues for testing"""
    dockerfile_content = """# Sample Dockerfile with intentional issues
FROM ubuntu:latest

# Running as root (security issue)
USER root

# Multiple RUN commands (optimization issue)
RUN apt-get update
RUN apt-get install -y python3 vim curl wget

# Hardcoded secret (security issue)
ENV API_KEY="secret123"

# Using ADD instead of COPY (security issue)
ADD app.py /app/

# Downloading over HTTP (security issue)
RUN wget http://example.com/file.tar.gz

# Exposing SSH port (best practice issue)
EXPOSE 22 8080

CMD ["python3", "/app/app.py"]
"""
    
    with open("Dockerfile.sample", "w") as f:
        f.write(dockerfile_content)
    print("📝 Created Dockerfile.sample for testing")

def main():
    parser = argparse.ArgumentParser(description="Analyze Dockerfiles for security and optimization issues")
    parser.add_argument("dockerfile", nargs="?", help="Path to Dockerfile")
    parser.add_argument("--create-sample", action="store_true", help="Create sample Dockerfile for testing")
    parser.add_argument("--scan-dir", help="Scan directory for Dockerfiles")
    
    args = parser.parse_args()
    
    if args.create_sample:
        create_sample_dockerfile()
        return
    
    analyzer = DockerfileAnalyzer()
    dockerfiles = []
    
    if args.scan_dir:
        # Scan directory for Dockerfiles
        dir_path = Path(args.scan_dir)
        dockerfiles = list(dir_path.glob("**/Dockerfile*"))
        dockerfiles.extend(dir_path.glob("**/dockerfile*"))
    elif args.dockerfile:
        dockerfiles = [Path(args.dockerfile)]
    else:
        # Look for Dockerfile in current directory
        current_dir = Path(".")
        dockerfiles = list(current_dir.glob("Dockerfile*"))
        dockerfiles.extend(current_dir.glob("dockerfile*"))
        
        if not dockerfiles:
            print("No Dockerfile found. Use --help for options.")
            return
    
    print(f"🔍 Analyzing {len(dockerfiles)} Dockerfile(s)...")
    
    total_issues = 0
    for dockerfile in dockerfiles:
        if dockerfile.is_file():
            issues = analyzer.analyze_file(str(dockerfile))
            generate_report(issues, str(dockerfile))
            total_issues += len(issues)
    
    print(f"\n📋 Total issues found across all files: {total_issues}")
    
    if total_issues > 0:
        print("\n💡 Pro Tips:")
        print("• Use multi-stage builds to reduce image size")
        print("• Create non-root users for better security")
        print("• Pin base image versions for reproducibility")
        print("• Chain RUN commands to reduce layers")
        print("• Use .dockerignore to exclude unnecessary files")

if __name__ == "__main__":
    main()