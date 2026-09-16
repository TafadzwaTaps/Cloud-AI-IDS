import pyodbc

conn = pyodbc.connect(
    "DRIVER={ODBC Driver 17 for SQL Server};"
    "SERVER=localhost,1433;"
    "DATABASE=CloudAI_IDS;"
    "UID=sa;"
    "PWD=Qwerty23$;"
    "Encrypt=yes;"
    "TrustServerCertificate=yes;"
)

print("✅ Connected to Docker SQL Server")
conn.close()
