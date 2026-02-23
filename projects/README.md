# Projects Directory

This directory contains project templates and reference materials for creating new projects.

## Directory Structure

```
projects/
├── README.md           # This file
├── template-project/   # Template for new projects (COPY THIS)
└── init/              # Reference materials for init project setup
```

## Creating a New Project

### Quick Start

```bash
# From style-guide root directory
cd projects/

# Copy template to new project name
cp -r template-project my-new-project

# Verify structure
ls -la my-new-project/
```

### What You Get

When you copy `template-project/`, you get:

```
my-new-project/
├── PRD.txt              # Product Requirements Document template
├── plans/               # Project planning documents
│   └── example-plan.md  # Example plan structure
├── resources/           # Project resources (diagrams, mockups, etc.)
│   └── README.md        # Resource organization guide
└── tasks/               # Task management files
    ├── example-tasks.json    # Full JSON Schema reference
    └── task-list-1.json      # Empty task list to start with
```

## Templates

### template-project/

**Purpose**: Starting point for all new projects

**Contents**:
- Empty PRD template with all standard sections
- Example plan structure
- Task file templates with JSON Schema
- Resource organization guide

**Usage**: Copy this directory to create a new project

**Do NOT**:
- Modify files in `template-project/` directly
- Use `template-project/` as an actual project
- Fill out the templates here

### init/

**Purpose**: Reference materials for the style-guide initialization

**Contents**:
- Example project structure
- Reference task files
- Planning examples

**Usage**: Reference only - shows how the init project was structured

## Workflow

### 1. Setup Phase

```bash
# Copy template
cp -r projects/template-project projects/my-project
```

Result: Empty project structure ready for planning

### 2. Planning Phase

Fill out the templates:
- Complete PRD.txt with project details
- Create tasks in task-list-1.json
- Add planning documents to plans/
- Define timeline and milestones

### 3. Development Phase

Execute and track:
- Work through tasks in priority order
- Update task status as work progresses
- Add resources to resources/ directory
- Create additional documentation as needed

## Task File Format

### Minimal Structure

```json
{
  "project": {
    "name": "Project Name",
    "version": "1.0.0"
  },
  "tasks": [
    {
      "id": "1",
      "title": "Task title",
      "description": "Brief description",
      "details": "Implementation details",
      "status": "pending",
      "priority": "high",
      "dependencies": [],
      "testStrategy": "How to verify completion"
    }
  ]
}
```

See `template-project/tasks/example-tasks.json` for complete schema.

## OpenCode Command

Use the OpenCode command for guided project setup:

```bash
# In OpenCode
@new-project
```

This command provides step-by-step guidance for:
1. Copying the template directory
2. Verifying structure
3. Understanding what NOT to do
4. Next steps for planning phase

## Validation

Validate task files after creating them:

```bash
# Validate single file
node scripts/validate-tasks.js projects/my-project/tasks/task-list-1.json

# Validate all tasks in project
node scripts/validate-tasks.js projects/my-project/tasks/*.json
```

## Documentation

- **[README.new-project.md](../docs/development/README.new-project.md)**: Complete new project setup guide
- **[README.task-management.md](../docs/development/README.task-management.md)**: Task management system documentation
- **[AGENTS.md](../AGENTS.md)**: AI agent guidelines and workflows

## Examples

### Example: Creating "Admin Dashboard" Project

```bash
# 1. Navigate to projects directory
cd projects/

# 2. Copy template
cp -r template-project admin-dashboard

# 3. Verify structure
ls -la admin-dashboard/
# Output: PRD.txt, plans/, resources/, tasks/

# 4. Structure is ready - move to planning phase
```

### Example: Project After Planning

```
projects/admin-dashboard/
├── PRD.txt                    # Completed with dashboard requirements
├── plans/
│   ├── phase-1-plan.md       # Created during planning
│   └── phase-2-plan.md       # Created during planning
├── resources/
│   ├── wireframes.png        # Added design assets
│   ├── api-spec.yaml         # Added API documentation
│   └── architecture.md       # Added architecture docs
└── tasks/
    ├── example-tasks.json    # Reference (unchanged)
    ├── phase-1-tasks.json    # Actual phase 1 tasks
    └── phase-2-tasks.json    # Actual phase 2 tasks
```

## Tips

- **Keep template-project pristine**: Never modify it directly
- **Reference example files**: Use example-tasks.json and example-plan.md as guides
- **Use descriptive names**: Name your project directories clearly
- **Validate early**: Run validation after creating tasks
- **Iterate on structure**: Add directories as needed (e.g., `docs/`, `scripts/`)

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Can't find template | Ensure you're in `projects/` directory |
| Permission denied | Check file permissions with `ls -la` |
| Validation fails | Review task schema in example-tasks.json |
| Missing directories | Re-copy from template-project |

---

_This directory structure enables organized, trackable project development using our task management system._


