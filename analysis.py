"""
Main module for running the mind2 preprocessing and analysis routines.
"""

from modules.mind2.db_preprocessing import start_preprocessing
from modules.mind2.process_mining import start_process_mining

if __name__ == "__main__":
    start_preprocessing()
    start_process_mining()
