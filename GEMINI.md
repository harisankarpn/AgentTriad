# AgentTriad Project Context

## Project Overview
Agent-Triad is an architectural blueprint and documentation repository for the Autonomous Cloud Operations (AaaS) platform. It outlines a closed-loop perception-reasoning-action-validation framework built on Google Cloud Agent as a Service (AaaS), utilizing the Agent Development Kit (ADK) and Agent2Agent (A2A) protocol.

## Key Files
- `README.md`: The central document defining the System Architecture (Central SaaS Control Plane vs. Customer GCP Data Plane) and the Agent Triad Lifecycle.
- `LICENSE`: Project license.

## Usage & Guidelines
- **Reference Material:** Use this repository as the primary reference for understanding the platform's multi-agent orchestration, security boundaries (e.g., Human-in-the-Loop authorization), and overall system design.
- **Development Workflow:** 
  - We are actively developing this project.
  - **CRITICAL RULE:** Every change made to the codebase MUST be committed and pushed to the repository ONLY AFTER explicit agreement and approval from the user.
  - **AUTHENTICATION RULE:** Always use `/home/harisankar/my-agent-lab/assessment-platform/get_token.py` to obtain the authentication token when pushing to the remote repository.

## Technical Notes
- The architecture enforces a strict decoupling between the SaaS Control Plane and Customer Data Plane.
- Key components include the Frontline Watcher, Troubleshooting Agent, and Execution Orchestrator.
