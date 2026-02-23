# Project Resources

This directory contains project resources such as diagrams, mockups, API specifications, design assets, and other supporting materials.

## Purpose

The `resources/` directory is a place to store non-code assets that support your project:

- **Diagrams**: Architecture diagrams, flowcharts, ER diagrams
- **Mockups**: UI mockups, wireframes, design comps
- **API Specifications**: OpenAPI/Swagger specs, API documentation
- **Design Assets**: Logos, icons, images, brand guidelines
- **Documentation**: Additional documentation not in main docs/
- **Research**: Research notes, competitive analysis, user research

## Directory Structure

```
resources/
├── diagrams/          # Architecture and flow diagrams
├── mockups/           # UI/UX mockups and wireframes
├── api/               # API specifications
├── design/            # Design assets and brand materials
├── research/          # Research notes and analysis
└── README.md          # This file
```

## Examples

### Architecture Diagrams

Store system architecture diagrams, component diagrams, and data flow diagrams here. Formats: PNG, SVG, Mermaid, PlantUML.

**Example**: `diagrams/system-architecture.png`

### UI Mockups

Store design mockups, wireframes, and prototypes. Formats: Figma links, PNG, PDF.

**Example**: `mockups/homepage-design.figma`

### API Specifications

Store OpenAPI/Swagger specifications, Postman collections, or API documentation.

**Example**: `api/openapi.yaml`

### Design Assets

Store logos, icons, images, and brand guidelines.

**Example**: `design/logo.svg`, `design/brand-guidelines.pdf`

## Best Practices

1. **Organize by type** - Use subdirectories for different resource types
2. **Name clearly** - Use descriptive filenames
3. **Version control** - Commit small assets, use Git LFS for large files
4. **Document** - Add README files in subdirectories explaining contents
5. **Keep updated** - Update resources as project evolves
6. **Link from docs** - Reference resources in project documentation

## Git Considerations

### Small Files

- Images under 1MB: Commit directly
- SVGs: Commit directly
- Text files: Commit directly

### Large Files

- Images over 1MB: Consider Git LFS or external storage
- Videos: Use external storage (not in repo)
- Large PDFs: Consider Git LFS

## Integration with Project

Reference resources in your project documentation:

```markdown
See [System Architecture Diagram](../resources/diagrams/system-architecture.png)
```

Link to resources from your PRD or project plan:

```markdown
## Design Resources

- [UI Mockups](../resources/mockups/)
- [Brand Guidelines](../resources/design/brand-guidelines.pdf)
```

## Example Resources from Style Guide Project

While the Style Guide Boilerplate project didn't require extensive resources, here are examples of what might be stored here:

- **Architecture Diagrams**: Next.js App Router structure, component hierarchy
- **API Specifications**: tRPC router structure, endpoint documentation
- **Design Assets**: Sirius brand colors, component library reference

## Related Documentation

- [Project Plan](../plans/) - Project planning documents
- [PRD](../PRD.txt) - Product requirements document
- [Tasks](../tasks/) - Task management files

---

_Use this directory to store supporting materials that help document and develop your project._
