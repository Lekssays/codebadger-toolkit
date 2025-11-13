"""
Query Template Parameter Registry

This module documents all available query templates and their parameters,
providing a central reference for template usage.
"""

from typing import Dict, List, Any

QUERY_TEMPLATES = {
    "core": {
        "list_methods": {
            "description": "List all methods in the CPG",
            "parameters": {
                "include_external": {
                    "type": "bool",
                    "default": False,
                    "description": "Include external/library methods"
                },
                "name_pattern": {
                    "type": "str",
                    "default": None,
                    "description": "Regex pattern for method names"
                },
                "file_pattern": {
                    "type": "str",
                    "default": None,
                    "description": "Regex pattern for file names"
                },
                "callee_pattern": {
                    "type": "str",
                    "default": None,
                    "description": "Regex pattern for methods that call a specific function"
                },
                "limit": {
                    "type": "int",
                    "default": 100,
                    "description": "Maximum number of results"
                }
            }
        },
        "get_method_source": {
            "description": "Get the source code of a specific method",
            "parameters": {
                "method_name": {
                    "type": "str",
                    "default": None,
                    "description": "Name of the method (regex pattern supported)"
                },
                "filename": {
                    "type": "str",
                    "default": None,
                    "description": "Optional filename to disambiguate methods"
                }
            }
        },
        "find_calls": {
            "description": "Find function/method calls in the codebase",
            "parameters": {
                "caller_pattern": {
                    "type": "str",
                    "default": None,
                    "description": "Regex to filter caller method names"
                },
                "callee_pattern": {
                    "type": "str",
                    "default": None,
                    "description": "Regex to filter callee method names"
                },
                "limit": {
                    "type": "int",
                    "default": 100,
                    "description": "Maximum number of results"
                }
            }
        },
        "find_literals": {
            "description": "Find literal values in the code",
            "parameters": {
                "pattern": {
                    "type": "str",
                    "default": None,
                    "description": "Regex to filter literal values"
                },
                "literal_type": {
                    "type": "str",
                    "default": None,
                    "description": "Type filter (e.g., 'string', 'int')"
                },
                "limit": {
                    "type": "int",
                    "default": 50,
                    "description": "Maximum number of results"
                }
            }
        },
        "call_graph": {
            "description": "Generate call graph for a method",
            "parameters": {
                "method_name": {
                    "type": "str",
                    "default": None,
                    "description": "Name of the method to analyze"
                },
                "depth": {
                    "type": "int",
                    "default": 5,
                    "description": "How many levels deep to traverse"
                },
                "direction": {
                    "type": "str",
                    "default": "outgoing",
                    "description": "Direction: 'outgoing' or 'incoming'"
                },
                "limit": {
                    "type": "int",
                    "default": 500,
                    "description": "Maximum number of results"
                }
            }
        },
        "list_parameters": {
            "description": "List parameters of a specific method",
            "parameters": {
                "method_name": {
                    "type": "str",
                    "default": None,
                    "description": "Name of the method (regex pattern supported)"
                }
            }
        }
    },
    "analysis": {
        "codebase_summary": {
            "description": "Get high-level summary of codebase structure",
            "parameters": {}
        },
        "bounds_checks": {
            "description": "Find bounds checks near buffer access",
            "parameters": {
                "buffer_access_location": {
                    "type": "str",
                    "default": None,
                    "description": "Location in format 'filename:line'"
                }
            }
        },
        "data_dependencies": {
            "description": "Analyze data dependencies for a variable",
            "parameters": {
                "location": {
                    "type": "str",
                    "default": None,
                    "description": "Location in format 'filename:line'"
                },
                "variable": {
                    "type": "str",
                    "default": None,
                    "description": "Variable name to analyze"
                },
                "direction": {
                    "type": "str",
                    "default": "backward",
                    "description": "Direction: 'backward' or 'forward'"
                }
            }
        },
        "program_slice": {
            "description": "Build program slice from a specific call node",
            "parameters": {
                "node_id": {
                    "type": "str",
                    "default": None,
                    "description": "CPG node ID of the target call"
                },
                "location": {
                    "type": "str",
                    "default": None,
                    "description": "Location in format 'filename:line' or 'filename:line:call_name'"
                },
                "include_dataflow": {
                    "type": "bool",
                    "default": True,
                    "description": "Include dataflow in slice"
                },
                "include_control_flow": {
                    "type": "bool",
                    "default": True,
                    "description": "Include control dependencies in slice"
                },
                "max_depth": {
                    "type": "int",
                    "default": 5,
                    "description": "Maximum depth for dataflow tracking"
                }
            }
        }
    },
    "taint": {
        "find_sources": {
            "description": "Find taint sources (external input points)",
            "parameters": {
                "patterns": {
                    "type": "str",
                    "default": None,
                    "description": "Pipe-separated regex patterns for source function names"
                },
                "filename": {
                    "type": "str",
                    "default": None,
                    "description": "Optional filename to filter results"
                },
                "limit": {
                    "type": "int",
                    "default": 200,
                    "description": "Maximum number of results"
                }
            }
        },
        "find_sinks": {
            "description": "Find taint sinks (dangerous functions)",
            "parameters": {
                "patterns": {
                    "type": "str",
                    "default": None,
                    "description": "Pipe-separated regex patterns for sink function names"
                },
                "filename": {
                    "type": "str",
                    "default": None,
                    "description": "Optional filename to filter results"
                },
                "limit": {
                    "type": "int",
                    "default": 200,
                    "description": "Maximum number of results"
                }
            }
        },
        "trace_flows": {
            "description": "Trace dataflow paths from source to sink",
            "parameters": {
                "source_node_id": {
                    "type": "str",
                    "default": None,
                    "description": "Node ID of source call"
                },
                "sink_node_id": {
                    "type": "str",
                    "default": None,
                    "description": "Node ID of sink call"
                },
                "max_path_length": {
                    "type": "int",
                    "default": 20,
                    "description": "Maximum length of dataflow paths"
                }
            }
        }
    }
}


def get_template_info(category: str, template_name: str) -> Dict[str, Any]:
    """Get information about a specific template"""
    if category not in QUERY_TEMPLATES:
        raise ValueError(f"Unknown category: {category}")
    
    if template_name not in QUERY_TEMPLATES[category]:
        raise ValueError(f"Unknown template: {template_name} in category {category}")
    
    return QUERY_TEMPLATES[category][template_name]


def list_templates_by_category(category: str) -> List[str]:
    """List all templates in a category"""
    if category not in QUERY_TEMPLATES:
        raise ValueError(f"Unknown category: {category}")
    
    return list(QUERY_TEMPLATES[category].keys())


def list_all_templates() -> Dict[str, List[str]]:
    """List all available templates organized by category"""
    return {
        category: list(templates.keys())
        for category, templates in QUERY_TEMPLATES.items()
    }
