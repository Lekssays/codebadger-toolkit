import logging
import os
from typing import Any, Dict, Optional, List
from ..exceptions import ValidationError
from ..utils.validators import validate_codebase_hash

logger = logging.getLogger(__name__)

class CodeBrowsingService:
    """Service for code browsing operations with caching support"""

    def __init__(self, codebase_tracker, query_executor, db_manager=None):
        self.codebase_tracker = codebase_tracker
        self.query_executor = query_executor
        self.db_manager = db_manager

    def _get_cached_or_execute(self, tool_name: str, codebase_hash: str, params: Dict[str, Any], query_func):
        """Helper to check cache, execute query if needed, and cache result"""
        if self.db_manager:
            cached = self.db_manager.get_cached_tool_output(tool_name, codebase_hash, params)
            if cached is not None:
                return cached

        result = query_func()
        
        if self.db_manager and result:
             # Only cache successful results that are not error dicts
             if isinstance(result, dict) and result.get("success", False):
                 self.db_manager.cache_tool_output(tool_name, codebase_hash, params, result)
        
        return result

    def list_methods(
        self,
        codebase_hash: str,
        name_pattern: Optional[str] = None,
        file_pattern: Optional[str] = None,
        callee_pattern: Optional[str] = None,
        include_external: bool = False,
        limit: int = 1000,
        page: int = 1,
        page_size: int = 100,
    ) -> Dict[str, Any]:
        
        validate_codebase_hash(codebase_hash)
        
        # Cache key parameters (excluding pagination)
        cache_params = {
            "name_pattern": name_pattern,
            "file_pattern": file_pattern,
            "callee_pattern": callee_pattern,
            "include_external": include_external,
        }

        def execute_query():
            codebase_info = self.codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}")

            query_parts = ["cpg.method"]
            if not include_external:
                query_parts.append(".isExternal(false)")
            if name_pattern:
                query_parts.append(f'.name("{name_pattern}")')
            if file_pattern:
                query_parts.append(f'.where(_.file.name("{file_pattern}"))')
            if callee_pattern:
                query_parts.append(f'.where(_.callOut.name("{callee_pattern}"))')

            query_parts.append(
                ".map(m => (m.name, m.id, m.fullName, m.signature, m.filename, m.lineNumber.getOrElse(-1), m.isExternal))"
            )
            
            query_limit = max(limit, 10000)
            query = "".join(query_parts) + f".dedup.take({query_limit}).l"
            
            result = self.query_executor.execute_query(
                codebase_hash=codebase_hash,
                cpg_path=codebase_info.cpg_path,
                query=query,
                timeout=30,
                limit=query_limit,
            )

            if not result.success:
                return {"success": False, "error": {"code": "QUERY_ERROR", "message": result.error}}

            methods = []
            for item in result.data:
                if isinstance(item, dict):
                    methods.append({
                        "node_id": str(item.get("_1", "")),
                        "name": item.get("_2", ""),
                        "fullName": item.get("_3", ""),
                        "signature": item.get("_4", ""),
                        "filename": item.get("_5", ""),
                        "lineNumber": item.get("_6", -1),
                        "isExternal": item.get("_7", False),
                    })
            return {"success": True, "methods": methods, "total": len(methods)}

        # Get full result (cached or fresh)
        full_result = self._get_cached_or_execute("list_methods", codebase_hash, cache_params, execute_query)
        
        if not full_result.get("success"):
            return full_result

        methods = full_result.get("methods", [])
        total = len(methods)
        
        # Pagination
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paged_methods = methods[start_idx:end_idx]

        return {
            "success": True,
            "methods": paged_methods,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size if page_size > 0 else 1
        }

    def list_files(
        self,
        codebase_hash: str,
        limit: int = 1000,
        page: int = 1,
        page_size: int = 100,
    ) -> Dict[str, Any]:
        
        validate_codebase_hash(codebase_hash)
        cache_params = {} # No filters for now

        def execute_query():
            codebase_info = self.codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}")

            query = f"cpg.file.map(f => (f.name, f.hash.getOrElse(\"\"))).take({limit}).l"
            
            result = self.query_executor.execute_query(
                codebase_hash=codebase_hash,
                cpg_path=codebase_info.cpg_path,
                query=query,
                timeout=30,
                limit=limit,
            )

            if not result.success:
                return {"success": False, "error": {"code": "QUERY_ERROR", "message": result.error}}

            files = []
            for item in result.data:
                if isinstance(item, dict):
                    files.append({
                        "name": item.get("_1", ""),
                        "hash": item.get("_2", ""),
                    })
            return {"success": True, "files": files, "total": len(files)}

        full_result = self._get_cached_or_execute("list_files", codebase_hash, cache_params, execute_query)
        
        if not full_result.get("success"):
            return full_result

        files = full_result.get("files", [])
        total = len(files)
        
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paged_files = files[start_idx:end_idx]

        return {
            "success": True,
            "files": paged_files,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size if page_size > 0 else 1
        }

    def list_calls(
        self,
        codebase_hash: str,
        caller_pattern: Optional[str] = None,
        callee_pattern: Optional[str] = None,
        limit: int = 1000,
        page: int = 1,
        page_size: int = 100,
    ) -> Dict[str, Any]:
        
        validate_codebase_hash(codebase_hash)
        cache_params = {
            "caller_pattern": caller_pattern,
            "callee_pattern": callee_pattern,
        }

        def execute_query():
            codebase_info = self.codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}")

            query_parts = ["cpg.call"]
            if callee_pattern:
                query_parts.append(f'.name("{callee_pattern}")')
            if caller_pattern:
                query_parts.append(f'.where(_.method.name("{caller_pattern}"))')

            query_parts.append(
                ".map(c => (c.method.name, c.name, c.code, c.method.filename, c.lineNumber.getOrElse(-1)))"
            )
            
            query_limit = max(limit, 10000)
            query = "".join(query_parts) + f".dedup.take({query_limit}).l"
            
            result = self.query_executor.execute_query(
                codebase_hash=codebase_hash,
                cpg_path=codebase_info.cpg_path,
                query=query,
                timeout=30,
                limit=query_limit,
            )

            if not result.success:
                return {"success": False, "error": {"code": "QUERY_ERROR", "message": result.error}}

            calls = []
            for item in result.data:
                if isinstance(item, dict):
                    calls.append({
                        "caller": item.get("_1", ""),
                        "callee": item.get("_2", ""),
                        "code": item.get("_3", ""),
                        "filename": item.get("_4", ""),
                        "lineNumber": item.get("_5", -1),
                    })
            return {"success": True, "calls": calls, "total": len(calls)}

        full_result = self._get_cached_or_execute("list_calls", codebase_hash, cache_params, execute_query)
        
        if not full_result.get("success"):
            return full_result

        calls = full_result.get("calls", [])
        total = len(calls)
        
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paged_calls = calls[start_idx:end_idx]

        return {
            "success": True,
            "calls": paged_calls,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size if page_size > 0 else 1
        }

    def list_parameters(
        self,
        codebase_hash: str,
        method_name: Optional[str] = None,
        limit: int = 1000,
    ) -> Dict[str, Any]:
        
        validate_codebase_hash(codebase_hash)
        cache_params = {"method_name": method_name}

        def execute_query():
            codebase_info = self.codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}")

            query_parts = ["cpg.method"]
            if method_name:
                query_parts.append(f'.name("{method_name}")')
            
            query_parts.append(
                '.map(m => (m.name, m.parameter.map(p => (p.name, p.typeFullName, p.index)).l))'
            )
            
            query = "".join(query_parts) + f".take({limit}).l"
            
            result = self.query_executor.execute_query(
                codebase_hash=codebase_hash,
                cpg_path=codebase_info.cpg_path,
                query=query,
                timeout=30,
                limit=limit,
            )

            if not result.success:
                return {"success": False, "error": {"code": "QUERY_ERROR", "message": result.error}}

            methods = []
            for item in result.data:
                if isinstance(item, dict) and "_1" in item and "_2" in item:
                    params = []
                    param_list = item.get("_2", [])
                    for param_data in param_list:
                        if isinstance(param_data, dict):
                            params.append({
                                "name": param_data.get("_1", ""),
                                "type": param_data.get("_2", ""),
                                "index": param_data.get("_3", -1),
                            })
                    methods.append({"method": item.get("_1", ""), "parameters": params})
            return {"success": True, "methods": methods, "total": len(methods)}

        return self._get_cached_or_execute("list_parameters", codebase_hash, cache_params, execute_query)

    def find_literals(
        self,
        codebase_hash: str,
        pattern: Optional[str] = None,
        literal_type: Optional[str] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        
        validate_codebase_hash(codebase_hash)
        cache_params = {
            "pattern": pattern,
            "literal_type": literal_type,
        }

        def execute_query():
            codebase_info = self.codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}")

            query_parts = ["cpg.literal"]
            if pattern:
                query_parts.append(f'.code("{pattern}")')
            if literal_type:
                query_parts.append(f'.typeFullName(".*{literal_type}.*")')

            query_parts.append(
                ".map(lit => (lit.code, lit.typeFullName, lit.filename, lit.lineNumber.getOrElse(-1), lit.method.name))"
            )
            
            query = "".join(query_parts) + f".take({limit}).l"
            
            result = self.query_executor.execute_query(
                codebase_hash=codebase_hash,
                cpg_path=codebase_info.cpg_path,
                query=query,
                timeout=30,
                limit=limit,
            )

            if not result.success:
                return {"success": False, "error": {"code": "QUERY_ERROR", "message": result.error}}

            literals = []
            for item in result.data:
                if isinstance(item, dict):
                    literals.append({
                        "value": item.get("_1", ""),
                        "type": item.get("_2", ""),
                        "filename": item.get("_3", ""),
                        "lineNumber": item.get("_4", -1),
                        "method": item.get("_5", ""),
                    })
            return {"success": True, "literals": literals, "total": len(literals)}

        return self._get_cached_or_execute("find_literals", codebase_hash, cache_params, execute_query)

    def warm_up_cache(self, codebase_hash: str):
        """Run default queries to warm up the cache in parallel"""
        logger.info(f"Warming up cache for codebase {codebase_hash}")
        
        import concurrent.futures
        
        tasks = [
            (self.list_methods, [codebase_hash]),
            (self.list_files, [codebase_hash]),
            (self.list_calls, [codebase_hash]),
            (self.list_parameters, [codebase_hash]),
            (self.find_literals, [codebase_hash])
        ]
        
        try:
            # Use ThreadPoolExecutor to run queries in parallel
            # We use 5 workers since we have 5 distinct tasks
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = {executor.submit(func, *args): func.__name__ for func, args in tasks}
                
                for future in concurrent.futures.as_completed(futures):
                    func_name = futures[future]
                    try:
                        future.result()
                        logger.info(f"Cache warm-up task {func_name} completed for {codebase_hash}")
                    except Exception as e:
                        logger.error(f"Cache warm-up task {func_name} failed for {codebase_hash}: {e}")
            
            logger.info(f"Cache warm-up complete for {codebase_hash}")
        except Exception as e:
            logger.error(f"Error during cache warm-up for {codebase_hash}: {e}")
