#!/usr/bin/env python3
"""Generate the prereq-guide.pdf from setup-checklist.md content."""

from fpdf import FPDF

class PrereqPDF(FPDF):
    def header(self):
        if self.page_no() == 1:
            self.set_font("Helvetica", "B", 22)
            self.set_text_color(26, 26, 46)
            self.cell(0, 14, "OSCAL Builder Session", new_x="LMARGIN", new_y="NEXT")
            self.set_font("Helvetica", "", 14)
            self.set_text_color(80, 80, 80)
            self.cell(0, 10, "Prerequisites Guide", new_x="LMARGIN", new_y="NEXT")
            self.set_font("Helvetica", "I", 10)
            self.cell(0, 8, "GRC Engineering Club", new_x="LMARGIN", new_y="NEXT")
            self.line(10, self.get_y() + 2, 200, self.get_y() + 2)
            self.ln(8)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(140, 140, 140)
        self.cell(0, 10, f"GRC Engineering Club - OSCAL Builder Session    |    Page {self.page_no()}/{{nb}}", align="C")

    def section_heading(self, text):
        self.ln(4)
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(22, 33, 62)
        self.cell(0, 10, text, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)

    def sub_heading(self, text):
        self.ln(2)
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(50, 50, 50)
        self.cell(0, 8, text, new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def body_text(self, text):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(40, 40, 40)
        self.multi_cell(0, 6, text)
        self.ln(2)

    def code_block(self, text):
        self.set_fill_color(244, 244, 244)
        self.set_draw_color(220, 220, 220)
        self.set_font("Courier", "", 9)
        self.set_text_color(40, 40, 40)
        x = self.get_x()
        w = self.w - self.l_margin - self.r_margin
        # Calculate height
        lines = text.strip().split("\n")
        h = len(lines) * 5 + 8
        # Check page break
        if self.get_y() + h > self.h - 20:
            self.add_page()
        y = self.get_y()
        self.rect(x, y, w, h, style="DF")
        self.set_xy(x + 4, y + 4)
        for i, line in enumerate(lines):
            self.cell(0, 5, line, new_x="LMARGIN", new_y="NEXT")
            if i < len(lines) - 1:
                self.set_x(x + 4)
        self.ln(4)

    def bullet(self, text, bold_prefix=""):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(40, 40, 40)
        x = self.get_x()
        self.cell(6, 6, "-")
        if bold_prefix:
            self.set_font("Helvetica", "B", 10)
            self.cell(self.get_string_width(bold_prefix) + 1, 6, bold_prefix)
            self.set_font("Helvetica", "", 10)
            self.multi_cell(0, 6, text)
        else:
            self.multi_cell(0, 6, text)
        self.ln(1)

    def numbered_item(self, num, text, bold_prefix=""):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(40, 40, 40)
        self.cell(8, 6, f"{num}.")
        if bold_prefix:
            self.set_font("Helvetica", "B", 10)
            self.cell(self.get_string_width(bold_prefix) + 1, 6, bold_prefix)
            self.set_font("Helvetica", "", 10)
        self.multi_cell(0, 6, text)
        self.ln(1)

    def warning_box(self, text):
        self.set_fill_color(255, 245, 245)
        self.set_draw_color(231, 76, 60)
        w = self.w - self.l_margin - self.r_margin
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(180, 40, 30)
        # Calculate box height based on text
        text_w = w - 10
        n_lines = max(1, len(self.multi_cell(text_w, 6, text, dry_run=True, output="LINES")))
        box_h = n_lines * 6 + 8
        y = self.get_y()
        if y + box_h > self.h - 20:
            self.add_page()
            y = self.get_y()
        # Draw background and left accent border
        self.rect(self.l_margin, y, w, box_h, style="DF")
        self.set_draw_color(231, 76, 60)
        self.line(self.l_margin, y, self.l_margin, y + box_h)
        self.line(self.l_margin + 0.8, y, self.l_margin + 0.8, y + box_h)
        self.set_xy(self.l_margin + 5, y + 4)
        self.multi_cell(text_w, 6, text)
        self.set_y(y + box_h + 4)


def build_pdf(output_path):
    pdf = PrereqPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    pdf.body_text("Complete these steps before the session. Budget 30-45 minutes.")

    # 1. Clone
    pdf.section_heading("1. Clone the Repository")
    pdf.code_block("git clone https://github.com/GRCJP/oscal-pipeline-workshop.git\ncd oscal-pipeline-workshop")

    # 2. Python
    pdf.section_heading("2. Python 3")
    pdf.body_text("You need Python 3.10 or newer.")
    pdf.sub_heading("Check if installed:")
    pdf.code_block("python3 --version")
    pdf.sub_heading("Install if needed:")
    pdf.bullet("macOS: ", bold_prefix="")
    pdf.code_block("brew install python3")
    pdf.bullet("Windows: Download from https://www.python.org/downloads/")
    pdf.bullet("Linux: ", bold_prefix="")
    pdf.code_block("sudo apt install python3 python3-pip")
    pdf.sub_heading("Install required packages:")
    pdf.code_block("pip3 install openpyxl python-docx python-dotenv boto3 pillow requests")

    # 3. AWS
    pdf.section_heading("3. AWS Free Tier Account")
    pdf.body_text("If you don't have one: https://aws.amazon.com/free/")
    pdf.sub_heading("Create an IAM user for the workshop")
    pdf.numbered_item(1, "Sign in to the AWS Console as root or admin")
    pdf.numbered_item(2, "Go to IAM > Users > Create user")
    pdf.numbered_item(3, 'Name: workshop-pipeline')
    pdf.numbered_item(4, "Attach policy: ReadOnlyAccess")
    pdf.numbered_item(5, 'Create an access key (select "Command Line Interface" use case)')
    pdf.numbered_item(6, "Save the Access Key ID and Secret Access Key - you'll need them for .env")

    pdf.sub_heading("Enable AWS Config")
    pdf.warning_box("IMPORTANT: Make sure you are in us-east-1 (check the region selector in the top right of the console).")
    pdf.numbered_item(1, "Go to AWS Config in the console")
    pdf.numbered_item(2, "Click Get started or Settings")
    pdf.numbered_item(3, "Select Record all resource types")
    pdf.numbered_item(4, "For S3 bucket, create a new one or use an existing bucket")
    pdf.numbered_item(5, "Let AWS create the service-linked role automatically")
    pdf.numbered_item(6, "Click Confirm")
    pdf.body_text("This gives the pipeline a complete inventory of your AWS resources.")
    pdf.sub_heading("Alternative: Run the setup script")
    pdf.code_block("bash scripts/aws-setup.sh")
    pdf.body_text("This creates all AWS resources in us-east-1 automatically.")

    pdf.sub_heading("Verify AWS CLI works")
    pdf.warning_box("All workshop resources must be in us-east-1 (N. Virginia). Using a different region will cause the pipeline to miss your resources.")
    pdf.code_block("brew install awscli   # macOS\n# or: pip3 install awscli\n\naws configure\n# Enter your Access Key ID, Secret Access Key, and region: us-east-1\n\n# Test connection:\naws iam list-users")

    # 4. GitHub
    pdf.section_heading("4. GitHub Personal Access Token")
    pdf.numbered_item(1, "Go to https://github.com/settings/tokens")
    pdf.numbered_item(2, "Click Generate new token (classic)")
    pdf.numbered_item(3, "Select scopes: repo, read:org")
    pdf.numbered_item(4, "Copy the token - you'll need it for .env")
    pdf.sub_heading("Test it:")
    pdf.code_block("export GITHUB_TOKEN=ghp_your_token_here\ngh auth status")

    # 5. Prowler
    pdf.section_heading("5. Prowler (Open Source Cloud Security Scanner)")
    pdf.code_block("pip3 install prowler")
    pdf.sub_heading("Verify:")
    pdf.code_block("prowler --version")
    pdf.body_text("Prowler uses your AWS credentials from .env. No separate account needed.")

    # 6. Trivy
    pdf.section_heading("6. Trivy (Container & IaC Scanner)")
    pdf.sub_heading("macOS:")
    pdf.code_block("brew install trivy")
    pdf.sub_heading("Linux:")
    pdf.code_block("sudo apt-get install wget apt-transport-https gnupg lsb-release\nwget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -\necho \"deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main\" | \\\n  sudo tee /etc/apt/sources.list.d/trivy.list\nsudo apt-get update && sudo apt-get install trivy")
    pdf.sub_heading("Windows:")
    pdf.code_block("choco install trivy")
    pdf.sub_heading("Verify:")
    pdf.code_block("trivy --version")

    # 7. Linear
    pdf.section_heading("7. Linear API Key (POA&M Issue Tracking)")
    pdf.body_text("Linear is used to create trackable issues from pipeline findings, each with evidence screenshots attached.")
    pdf.numbered_item(1, "Go to https://linear.app/settings/api")
    pdf.numbered_item(2, "Click Create key")
    pdf.numbered_item(3, "Copy the API key - you'll need it for .env")
    pdf.sub_heading("Find your team key:")
    pdf.body_text('Your team key is the short prefix on issues (e.g., "GRC" if issues are GRC-1, GRC-2). Check it under Settings > Teams.')

    # 8. Configure Environment
    pdf.section_heading("8. Configure Your Environment")
    pdf.numbered_item(1, "Copy the example environment file:")
    pdf.code_block("cp prereqs/.env.example .env")
    pdf.numbered_item(2, "Open .env and fill in your credentials:")
    pdf.code_block("open .env        # macOS\nnotepad .env     # Windows\nnano .env        # Linux/terminal")
    pdf.numbered_item(3, "Load the environment:")
    pdf.code_block('export $(cat .env | grep -v \'^#\' | xargs)')

    # 9. Verify
    pdf.section_heading("9. Verify Everything Works")
    pdf.body_text("Run the converter to confirm your setup:")
    pdf.code_block("python3 scripts/excel_to_oscal.py \\\n  --input Templates/fedramp-moderate-template-ssp.xlsx \\\n  --output oscal")
    pdf.body_text("You should see 57 controls processed and CONVERSION COMPLETE.")
    pdf.sub_heading("Run the full pipeline (all 6 stages end-to-end):")
    pdf.code_block("python3 scripts/run_pipeline.py --github-repo oscal-pipeline-workshop")
    pdf.body_text("This runs: Convert, Discover, Assess, Reconcile, Enforce, and Report (including Linear export with evidence screenshots).")

    # Tool Summary Table
    pdf.section_heading("Tool Summary")
    col_widths = [32, 60, 30, 68]
    headers = ["Tool", "Purpose", "Cost", "Install"]
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(26, 26, 46)
    pdf.set_text_color(255, 255, 255)
    for i, h in enumerate(headers):
        pdf.cell(col_widths[i], 8, h, border=1, fill=True)
    pdf.ln()

    tools = [
        ("Python 3", "Run pipeline scripts", "Free", "brew install python3"),
        ("boto3", "AWS SDK for Python", "Free", "pip3 install boto3"),
        ("python-dotenv", "Load .env credentials", "Free", "pip3 install python-dotenv"),
        ("AWS CLI", "Query AWS APIs", "Free tier", "brew install awscli"),
        ("AWS Config", "Asset discovery & inventory", "Free tier", "AWS Console"),
        ("GitHub + Token", "Source control evidence", "Free", "github.com/settings/tokens"),
        ("Linear", "POA&M issue tracking", "Free", "linear.app/settings/api"),
        ("Prowler", "Cloud security posture", "Free (OSS)", "pip3 install prowler"),
        ("Trivy", "Container/IaC scanning", "Free (OSS)", "brew install trivy"),
        ("NVD API", "Vulnerability intelligence", "Free", "No install needed"),
        ("CodeQL", "SAST code scanning", "Free", "Runs via GitHub Actions"),
    ]

    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(40, 40, 40)
    for row in tools:
        for i, val in enumerate(row):
            pdf.cell(col_widths[i], 7, val, border=1)
        pdf.ln()

    # Troubleshooting
    pdf.section_heading("Troubleshooting")
    troubles = [
        ("python: command not found", "Use python3 instead of python. macOS does not ship with python."),
        ("aws: command not found", "Install AWS CLI: brew install awscli or pip3 install awscli"),
        ("AWS access denied errors", "Check that your IAM user has ReadOnlyAccess policy attached."),
        ("GitHub token not working", "Make sure you selected repo and read:org scopes when creating the token."),
        ("Linear issues not creating", "Check that LINEAR_API_KEY and LINEAR_TEAM_KEY are set in .env. The team key is the short prefix on your issues (e.g., GRC)."),
    ]
    for error, fix in troubles:
        pdf.set_font("Courier", "B", 9)
        pdf.set_text_color(180, 40, 30)
        pdf.cell(0, 6, error, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(40, 40, 40)
        pdf.multi_cell(0, 6, fix)
        pdf.ln(3)

    # Questions
    pdf.section_heading("Questions?")
    pdf.body_text("Reach out in the GRC Engineering Club channel before the session.")

    pdf.output(output_path)
    print(f"PDF generated: {output_path}")


if __name__ == "__main__":
    build_pdf("/Users/jleepe/CascadeProjects/repo/GRC Club Demo/prereq-guide.pdf")
