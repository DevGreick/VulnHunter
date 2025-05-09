# src/exceptions.py

class ParserError(Exception):
    """Custom exception for dependency file parsing errors."""
    pass

class NvdDataError(Exception):
    """Custom exception for NVD data loading or processing errors."""
    pass

class AnalysisError(Exception):
    """Custom exception for vulnerability analysis errors."""
    pass
