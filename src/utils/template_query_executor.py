"""
Query Executor with Template Support

Provides functionality to execute queries using the template system.
Combines query loading, rendering, and execution.
"""

import logging
from typing import Dict, Any, Optional

from .query_loader import get_query_loader
from .query_registry import get_template_info

logger = logging.getLogger(__name__)


class TemplateQueryExecutor:
    """Execute queries using template system"""

    def __init__(self, query_executor_service):
        """
        Initialize the template query executor.

        Args:
            query_executor_service: The underlying query executor service
        """
        self.query_executor = query_executor_service
        self.template_loader = get_query_loader()

    async def execute_template_query(
        self,
        session_id: str,
        category: str,
        template_name: str,
        params: Dict[str, Any],
        timeout: int = 300,
        limit: Optional[int] = 150,
        offset: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Load a template, render it with parameters, and execute the query.

        Args:
            session_id: The session ID
            category: Template category (e.g., 'core', 'analysis', 'taint')
            template_name: Template name (e.g., 'list_methods')
            params: Parameters for template rendering
            timeout: Query execution timeout in seconds
            limit: Maximum number of results
            offset: Result offset for pagination

        Returns:
            Query result dictionary

        Raises:
            FileNotFoundError: If template doesn't exist
            ValueError: If template rendering fails
        """
        try:
            # Get template info for validation
            template_info = get_template_info(category, template_name)
            logger.info(f"Executing template query: {category}/{template_name}")

            # Load and render template
            query = self.template_loader.load_and_render(
                category=category,
                name=template_name,
                params=params,
            )

            logger.debug(f"Rendered query:\n{query}")

            # Execute the query
            result = await self.query_executor.execute_query(
                session_id=session_id,
                cpg_path="/workspace/cpg.bin",
                query=query,
                timeout=timeout,
                limit=limit,
                offset=offset,
            )

            return result

        except FileNotFoundError as e:
            logger.error(f"Template not found: {e}")
            raise
        except Exception as e:
            logger.error(f"Error executing template query: {e}", exc_info=True)
            raise

    def get_template_documentation(self, category: str, template_name: str) -> Dict[str, Any]:
        """Get documentation for a template"""
        return get_template_info(category, template_name)
