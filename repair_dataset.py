import pandas as pd
import os

file_path = "backend/legitphish.csv"
if os.path.exists(file_path):
    try:
        # Читаем с ошибкой, игнорируя плохие строки
        df = pd.read_csv(file_path, on_bad_lines='skip')
        
        # Приводим метку к 0/1
        # Если там было True/False, превращаем в 1/0
        if df['IsMalicious'].dtype == 'object':
            df['IsMalicious'] = df['IsMalicious'].map({'True': 1, 'False': 0, '1': 1, '0': 0}).fillna(0).astype(int)
        else:
            # Если числа, то всё что не 0 -> 1
            df['IsMalicious'] = df['IsMalicious'].apply(lambda x: 1 if x > 0 else 0).astype(int)
            
        df.to_csv(file_path, index=False)
        print(f"✅ CSV очищен. Осталось строк: {len(df)}")
    except Exception as e:
        print(f"❌ Ошибка очистки: {e}")
else:
    print("Файл не найден")