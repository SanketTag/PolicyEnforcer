# 🛡️ PolicyEnforcer - Azure DevOps Branch Security Automation

## 📌 Overview

PolicyEnforcer is a **PowerShell-based automation solution** designed to **enforce branch policies and permissions** in **Azure DevOps**.\
It ensures that security settings are **applied consistently** across repositories, preventing unauthorized changes and enforcing compliance.

---

## 🔧 Features

✔ **Automated Branch Security** – Enforces branch policies using Azure DevOps REST API\
✔ **RBAC Implementation** – Ensures **least privilege access** and prevents unauthorized edits\
✔ **Deny "Edit Policies"** – Prevents non-admins from modifying security settings\
✔ **Supports Multiple Groups** – Configurable permissions for different user roles\
✔ **Infrastructure-as-Code** – Policies are enforced via an **Azure DevOps pipeline**\
✔ **Secure Authentication** – Uses a **dedicated service account** for policy enforcement

---

## 📂 Project Structure

```
PolicyEnforcer/
️️️modules/                    # PowerShell modules for policy enforcement  
️️scripts/                     # PowerShell scripts used in YAML pipeline  
️️azure-pipelines.yml          # Azure DevOps pipeline for enforcement  
️️variables.yml                # YAML file for configurable parameters  
️️README.md                    # Project documentation  
️️.gitignore                    # Excluded files  
```

---

## 🛠️ How It Works

1️⃣ The **Azure DevOps Pipeline** runs the PowerShell scripts to check and enforce security policies.\
2️⃣ It **retrieves the default branch** of a given repository.\
3️⃣ It **checks if branch permissions** (e.g., "Edit Policies", "Force Push", "Bypass Policies When Completing PRs", "Bypass Policies When Pushing") are set correctly.\
4️⃣ It **checks if branch policies** (e.g., "Minimum number of reviewers") are applied.\
5️⃣ If any security settings are missing, it **applies the necessary permissions and policies**.

---

## ⚙️ Prerequisites

✔ **Azure DevOps Account** with admin privileges\
✔ **Dedicated Service Account** with required permissions\
✔ **Personal Access Token (PAT)** stored in Azure DevOps Library

---

## 🚀 Setup & Execution

### **🔹 Step 1: Configure Variable Group in Azure DevOps**

1️⃣ Go to **Azure DevOps → Pipelines → Library**\
2️⃣ Create a new **Variable Group** called ``\
3️⃣ Add the following variables:

- `ADMIN_SERVICE_PAT` → **Store the Personal Access Token (PAT) securely**

### **🔹 Step 2: Deploy the Pipeline**

1️⃣ Navigate to **Azure DevOps → Pipelines**\
2️⃣ Click **"New Pipeline"**\
3️⃣ Select **"GitHub Repository"** and choose this repo\
4️⃣ Select **"Existing YAML file"** and choose `azure-pipelines.yml`\
5️⃣ Click **"Run Pipeline"**

---

## 📜 Branch Policies Enforced

PolicyEnforcer ensures the following branch policies:\
✔ **Deny "Edit Policies", "Force Push", "Bypass Policies When Completing PRs", "Bypass Policies When Pushing"** to all project level security groups "Build Administrators", "Contributors", "Project Administrators", "Project Valid Users", "Readers"\
✔ **Enforce Minimum 2 Approvers** for Pull Requests\
✔ **Reset Approval Votes** on new changes
✔ Only **Organisation level admin** only can enforce or edit policies and permissions.

---

## 🏆 Best Practices

✔ **Use Role-Based Access Control (RBAC)** – Assign permissions to groups instead of individuals\
✔ **Use a Dedicated Admin Service Account** – Avoid using personal accounts for enforcement with least required privileges\
✔ **Store Secrets Securely** – Use Azure DevOps Library to store PATs\
✔ **Automate Policy Enforcement** – Ensure policies are applied via pipelines

---

