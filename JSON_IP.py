import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Загрузка данных из JSON-файла
with open('botsv1.json', 'r') as f:
    data = json.load(f)

# Извлечение результатов и создание DataFrame
results = [item['result'] for item in data if 'result' in item]
df = pd.DataFrame(results)

# Нормализация: обработка списков в столбцах, если они есть (например, eventtype)
if 'eventtype' in df.columns:
    df['eventtype_str'] = df['eventtype'].apply(lambda x: ' '.join(x) if isinstance(x, list) else str(x))
else:
    df['eventtype_str'] = ''

# Разделение на WinEventLog (Security) и DNS
win_df = df[df.get('LogName') == 'Security'].copy()
dns_df = df[df.get('LogName') == 'DNS'].copy()

# Анализ WinEventLog: подозрительные EventCode
# 4624: успешный логон (сетевой тип 3 - потенциально подозрительный)
# 4625: неудачный логон (входы с ошибками)
# 4703: изменение прав пользователя (эскалация привилегий)
susp_win_codes = ['4624', '4625', '4703']
susp_win = win_df[win_df['EventCode'].isin(susp_win_codes)].copy()
susp_win['susp_type'] = susp_win['EventCode'] + ' - ' + susp_win.get('signature', 'Нет описания') + ' (' + susp_win.get('TaskCategory', '') + ')'

# Анализ DNS: подозрительные запросы
# Фильтрация по ключевым словам в eventtype (suspicious, beaconing)
# Дополнительно: подозрительные по длине имени или необычным доменам (например, длинные случайные строки)
susp_dns = dns_df[dns_df['eventtype_str'].str.contains('suspicious|beaconing', case=False, na=False)].copy()

# Дополнительный фильтр для DNS: редкие домены (например, с цифрами или случайными строками)
# Здесь простой пример: домены с цифрами в имени или длиннее 20 символов
susp_dns['is_susp_domain'] = susp_dns['QueryName'].apply(lambda x: any(c.isdigit() for c in x) or len(x) > 20 if pd.notna(x) else False)
susp_dns = susp_dns[susp_dns['is_susp_domain'] | dns_df['eventtype_str'].str.contains('suspicious|beaconing', case=False, na=False)]

susp_dns['susp_type'] = susp_dns['QueryName'] + ' (' + susp_dns['eventtype_str'] + ')'

# Вывод информации о найденных подозрительных событиях
print(f"Подозрительных событий в WinEventLog: {len(susp_win)}")
print(f"Подозрительных запросов в DNS: {len(susp_dns)}")

# Топ-10 для WinEventLog
top_win = susp_win['susp_type'].value_counts().head(10)
print("\nТоп-10 подозрительных событий WinEventLog:\n", top_win)

# Топ-10 для DNS
top_dns = susp_dns['susp_type'].value_counts().head(10)
print("\nТоп-10 подозрительных DNS-запросов:\n", top_dns)

# Визуализация: две отдельные диаграммы
plt.figure(figsize=(14, 12))

# График для WinEventLog
plt.subplot(2, 1, 1)
sns.barplot(x=top_win.values, y=top_win.index, palette='viridis')
plt.title('Топ-10 подозрительных событий в WinEventLog (Security)')
plt.xlabel('Количество происшествий')
plt.ylabel('Тип события')

# График для DNS
plt.subplot(2, 1, 2)
sns.barplot(x=top_dns.values, y=top_dns.index, palette='magma')
plt.title('Топ-10 подозрительных DNS-запросов')
plt.xlabel('Количество происшествий')
plt.ylabel('Тип запроса')

plt.tight_layout()
plt.savefig('suspicious_events_visualization.png')
plt.show()

# Краткий вывод
print("\nАнализ завершён. Подозрительные события выделены на основе кодов событий и меток. Визуализация сохранена в файл 'suspicious_events_visualization.png'.")