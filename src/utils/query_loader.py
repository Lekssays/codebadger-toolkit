"""
Query Template Loader and Manager

Provides functionality to load and manage Joern query templates from disk.
Templates use Jinja2 syntax for parameter substitution and conditional rendering.
"""

import os
import logging
from typing import Dict, Any, Optional
from pathlib import Path

try:
    from jinja2 import Environment, FileSystemLoader, TemplateNotFound
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

logger = logging.getLogger(__name__)


class QueryTemplateLoader:
    """Load and manage query templates from files"""

    def __init__(self, templates_dir: Optional[str] = None):
        """
        Initialize the query template loader.

        Args:
            templates_dir: Path to queries directory. If None, uses default location.
        """
        if templates_dir is None:
            # Default to queries directory relative to this file
            project_root = Path(__file__).parent.parent.parent
            templates_dir = os.path.join(project_root, "queries")

        self.templates_dir = os.path.abspath(templates_dir)
        self._cache: Dict[str, str] = {}
        
        # Initialize Jinja2 environment if available
        if JINJA2_AVAILABLE:
            self.env = Environment(
                loader=FileSystemLoader(self.templates_dir),
                trim_blocks=True,
                lstrip_blocks=True,
                keep_trailing_newline=True,
            )
        else:
            self.env = None
            logger.warning("Jinja2 not available - using simple string substitution")
        
        logger.info(f"Initialized QueryTemplateLoader with templates_dir: {self.templates_dir}")

    def load_template(self, category: str, name: str) -> str:
        """
        Load a query template from file.

        Args:
            category: Category subdirectory (e.g., 'core', 'analysis', 'taint')
            name: Template filename without extension (e.g., 'list_methods')

        Returns:
            Template content as string

        Raises:
            FileNotFoundError: If template file doesn't exist
        """
        cache_key = f"{category}/{name}"

        # Check cache first
        if cache_key in self._cache:
            logger.debug(f"Cache hit for template: {cache_key}")
            return self._cache[cache_key]

        # Construct file path
        template_path = os.path.join(self.templates_dir, category, f"{name}.sc")

        # Check if file exists
        if not os.path.exists(template_path):
            available = self._list_available_templates(category)
            raise FileNotFoundError(
                f"Query template not found: {template_path}\n"
                f"Available templates in '{category}': {available}"
            )

        # Load from file
        try:
            with open(template_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Cache the template
            self._cache[cache_key] = content
            logger.info(f"Loaded template: {cache_key}")
            return content

        except Exception as e:
            logger.error(f"Error loading template {template_path}: {e}")
            raise

    def render_template(self, template: str, params: Dict[str, Any]) -> str:
        """
        Render a template with the given parameters.

        Uses Jinja2 syntax:
        - {{param_name}} for variables
        - {%if condition%}...{%endif%} for conditionals
        - {%for item in items%}...{%endfor%} for loops

        Args:
            template: Template string
            params: Dictionary of parameters to substitute

        Returns:
            Rendered template string

        Raises:
            ValueError: If rendering fails
        """
        if not JINJA2_AVAILABLE:
            raise ValueError(
                "Jinja2 is required for template rendering. "
                "Install it with: pip install jinja2"
            )

        try:
            # Render the template using Jinja2
            tmpl = self.env.from_string(template)
            result = tmpl.render(**params)
            return result

        except Exception as e:
            logger.error(f"Error rendering template: {e}")
            raise ValueError(f"Template rendering failed: {e}")

    def render_template_safe(
        self, template: str, params: Dict[str, Any], defaults: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Render a template with the given parameters, using defaults for missing ones.

        Args:
            template: Template string
            params: Dictionary of parameters to substitute
            defaults: Dictionary of default values for missing parameters

        Returns:
            Rendered template string
        """
        defaults = defaults or {}
        merged_params = {**defaults, **params}
        return self.render_template(template, merged_params)

    def load_and_render(
        self,
        category: str,
        name: str,
        params: Dict[str, Any],
        defaults: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Load a template and render it with the given parameters in one call.

        Args:
            category: Category subdirectory (e.g., 'core', 'analysis', 'taint')
            name: Template filename without extension
            params: Dictionary of parameters to substitute
            defaults: Dictionary of default values for missing parameters

        Returns:
            Rendered template string
        """
        template = self.load_template(category, name)
        return self.render_template_safe(template, params, defaults)

    def _list_available_templates(self, category: str) -> list:
        """List available templates in a category directory."""
        category_path = os.path.join(self.templates_dir, category)

        if not os.path.exists(category_path):
            return []

        templates = []
        for filename in os.listdir(category_path):
            if filename.endswith(".sc"):
                templates.append(filename[:-3])  # Remove .sc extension

        return templates

    def list_templates(self, category: Optional[str] = None) -> Dict[str, list]:
        """
        List all available templates.

        Args:
            category: If provided, only list templates in this category

        Returns:
            Dictionary mapping category names to lists of template names
        """
        result = {}

        if category:
            # List templates in specific category
            result[category] = self._list_available_templates(category)
        else:
            # List templates in all categories
            if os.path.exists(self.templates_dir):
                for item in os.listdir(self.templates_dir):
                    item_path = os.path.join(self.templates_dir, item)
                    if os.path.isdir(item_path):
                        result[item] = self._list_available_templates(item)

        return result

    def clear_cache(self):
        """Clear the template cache."""
        self._cache.clear()
        logger.info("Cleared template cache")


# Global instance
_loader_instance: Optional[QueryTemplateLoader] = None


def get_query_loader(templates_dir: Optional[str] = None) -> QueryTemplateLoader:
    """
    Get or create the global query template loader instance.

    Args:
        templates_dir: Path to queries directory (only used on first call)

    Returns:
        QueryTemplateLoader instance
    """
    global _loader_instance

    if _loader_instance is None:
        _loader_instance = QueryTemplateLoader(templates_dir)

    return _loader_instance
