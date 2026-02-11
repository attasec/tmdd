"""TMDD init command - Initialize a new TMDD project."""
from pathlib import Path

from ..utils import get_project_root, TMDDError


def cmd_init(args):
    """Initialize a new TMDD project."""
    templates_dir = get_project_root() / "templates"
    if not templates_dir.is_dir():
        raise TMDDError(f"Templates not found: {templates_dir}")

    available = [d.name for d in templates_dir.iterdir() if d.is_dir()]
    if args.list:
        print("Templates:", ", ".join(available))
        return 0

    template_path = templates_dir / args.template
    if not template_path.is_dir():
        raise TMDDError(f"Template '{args.template}' not found. Available: {', '.join(available)}")

    dest = Path(args.path)
    dest.mkdir(parents=True, exist_ok=True)

    created, skipped = [], []
    for src in template_path.rglob("*"):
        if not src.is_file():
            continue
        rel = src.relative_to(template_path)
        dst = dest / rel
        if dst.exists():
            skipped.append(str(rel))
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            content = (
                src.read_text(encoding="utf-8")
                .replace("{{name}}", args.name)
                .replace("{{description}}", args.description)
            )
            dst.write_text(content, encoding="utf-8")
            created.append(str(rel))

    print(f"\nTMDD initialized: {dest.absolute()} (template: {args.template})")
    if created:
        preview = ", ".join(sorted(created)[:5])
        suffix = "..." if len(created) > 5 else ""
        print(f"Created {len(created)} files: {preview}{suffix}")
    if skipped:
        print(f"Skipped {len(skipped)} existing files")
    print(f"\nNext: tmdd lint -> tmdd feature \"Login\" -> tmdd compile")
    return 0
