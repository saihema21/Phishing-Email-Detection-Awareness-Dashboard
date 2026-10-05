import sqlite3
from datetime import datetime


DATABASE_PATH = "data/phishing_analysis.db"


def initialize_database():
    connection = sqlite3.connect(DATABASE_PATH)

    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS analyses (
            analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_domain TEXT,
            subject TEXT,
            risk_score INTEGER,
            classification TEXT,
            indicators TEXT,
            analyzed_at TEXT
        )
        """
    )

    connection.commit()
    connection.close()


def save_analysis(
    sender_domain,
    subject,
    risk_score,
    classification,
    indicators
):
    connection = sqlite3.connect(DATABASE_PATH)

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO analyses (
            sender_domain,
            subject,
            risk_score,
            classification,
            indicators,
            analyzed_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            sender_domain,
            subject,
            risk_score,
            classification,
            "; ".join(indicators),
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )
    )

    connection.commit()
    connection.close()


def get_analysis_history():
    connection = sqlite3.connect(DATABASE_PATH)

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            analysis_id,
            sender_domain,
            subject,
            risk_score,
            classification,
            indicators,
            analyzed_at
        FROM analyses
        ORDER BY analysis_id DESC
        """
    )

    rows = cursor.fetchall()

    connection.close()

    return rows