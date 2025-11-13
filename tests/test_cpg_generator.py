"""
Tests for CPG generator (subprocess-based with joern-parse)
"""

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.constants import CPGS_DIR, CPG_FILENAME
from src.exceptions import CPGGenerationError
from src.models import CPGConfig, SessionStatus, Config, JoernConfig
from src.services.cpg_generator import CPGGenerator
from src.services.session_manager import SessionManager


class TestCPGGenerator:
    """Test CPG generator functionality"""

    @pytest.fixture
    def config(self):
        """Configuration fixture"""
        return Config(
            cpg=CPGConfig(
                generation_timeout=600,
                max_repo_size_mb=500,
                supported_languages=["java", "python", "c", "cpp"],
            ),
            joern=JoernConfig(
                binary_path="joern-parse",
                memory_limit="4g",
                java_opts="-Xmx4G -Xms2G -XX:+UseG1GC -Dfile.encoding=UTF-8"
            )
        )

    @pytest.fixture
    def mock_session_manager(self):
        """Mock session manager fixture"""
        return AsyncMock(spec=SessionManager)

    @pytest.fixture
    def cpg_generator(self, config, mock_session_manager):
        """CPG generator fixture"""
        generator = CPGGenerator(config, mock_session_manager)
        return generator

    @pytest.mark.asyncio
    async def test_initialize_success(self, cpg_generator):
        """Test successful initialization"""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="/usr/bin/joern-parse")
            await cpg_generator.initialize()
            # Should not raise an exception

    @pytest.mark.asyncio
    async def test_initialize_failure(self, cpg_generator):
        """Test initialization failure when joern-parse not found"""
        with patch("subprocess.run", side_effect=Exception("joern-parse not found")):
            with pytest.raises(CPGGenerationError):
                await cpg_generator.initialize()

    @pytest.mark.asyncio
    async def test_generate_cpg_success(self, cpg_generator):
        """Test successful CPG generation"""
        mock_session_manager = cpg_generator.session_manager

        with patch.object(cpg_generator, "_exec_command_async") as mock_exec, \
             patch.object(cpg_generator, "_validate_cpg_async", return_value=True) as mock_validate, \
             patch("os.makedirs"):

            mock_exec.return_value = ("success", "")

            cpg_path = await cpg_generator.generate_cpg(
                session_id="test-session",
                source_path="/code/src",
                language="java"
            )

            # Verify session was updated
            mock_session_manager.update_status.assert_called_once()
            # Check that the status includes 'generating'
            call_args = mock_session_manager.update_status.call_args
            assert call_args[0][1] == "generating"  # Second arg should be the status

            # Verify execution was called with joern-parse command
            mock_exec.assert_called_once()
            call_args = mock_exec.call_args[0][0]
            assert "joern-parse" in call_args
            assert "/code/src" in call_args

            # Verify CPG path contains session ID
            assert "test-session" in cpg_path
            assert CPG_FILENAME in cpg_path

    @pytest.mark.asyncio
    async def test_generate_cpg_timeout(self, cpg_generator):
        """Test CPG generation timeout"""
        mock_session_manager = cpg_generator.session_manager

        with patch.object(cpg_generator, "_exec_command_async") as mock_exec, \
             patch("os.makedirs"):

            mock_exec.side_effect = asyncio.TimeoutError()

            with pytest.raises(CPGGenerationError) as exc_info:
                await cpg_generator.generate_cpg(
                    session_id="test-session",
                    source_path="/code/src"
                )

            assert "timed out" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_generate_cpg_validation_failure(self, cpg_generator):
        """Test CPG generation when validation fails"""
        mock_session_manager = cpg_generator.session_manager

        with patch.object(cpg_generator, "_exec_command_async") as mock_exec, \
             patch.object(cpg_generator, "_validate_cpg_async", return_value=False) as mock_validate, \
             patch("os.makedirs"):

            mock_exec.return_value = ("success", "")

            with pytest.raises(CPGGenerationError) as exc_info:
                await cpg_generator.generate_cpg(
                    session_id="test-session",
                    source_path="/code/src"
                )

            assert "not created" in str(exc_info.value).lower() or "empty" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_validate_cpg_success(self, cpg_generator):
        """Test successful CPG validation"""
        with patch("os.path.exists", return_value=True), \
             patch("os.path.getsize", return_value=10000):

            result = await cpg_generator._validate_cpg_async("/path/to/cpg.bin")
            assert result is True

    @pytest.mark.asyncio
    async def test_validate_cpg_not_found(self, cpg_generator):
        """Test CPG validation when file not found"""
        with patch("os.path.exists", return_value=False):
            result = await cpg_generator._validate_cpg_async("/path/to/cpg.bin")
            assert result is False

    @pytest.mark.asyncio
    async def test_validate_cpg_too_small(self, cpg_generator):
        """Test CPG validation when file is too small"""
        with patch("os.path.exists", return_value=True), \
             patch("os.path.getsize", return_value=512):  # Too small

            result = await cpg_generator._validate_cpg_async("/path/to/cpg.bin")
            assert result is False

    @pytest.mark.asyncio
    async def test_exec_command_async_success(self, cpg_generator):
        """Test async command execution"""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="command output",
                stderr=""
            )

            stdout, stderr = await cpg_generator._exec_command_async(
                ["echo", "test"]
            )

            assert stdout == "command output"
            assert stderr == ""

    @pytest.mark.asyncio
    async def test_exec_command_async_failure(self, cpg_generator):
        """Test async command execution failure"""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="", 
                stderr="error occurred", 
                returncode=1
            )
            stdout, stderr = await cpg_generator._exec_command_async(["false"])
            assert stderr == "error occurred"
