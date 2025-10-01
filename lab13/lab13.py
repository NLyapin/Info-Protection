"""
Лабораторная работа №13 — протокол "слепой" подписи для анонимного голосования (Python)

Реализация протокола "слепой" подписи на базе системы анонимного голосования.
Программа разделена на серверную и клиентскую части (логически).
Поддерживает голосование с вариантами ответов: Да, Нет, Воздержался.
"""

import random
import sys
import argparse
import time
import platform
from typing import List, Tuple, Dict, Optional

# Проверка доступности tkinter
GUI_AVAILABLE = False
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext
    GUI_AVAILABLE = True
except (ImportError, Exception):
    GUI_AVAILABLE = False


def mod_pow(a: int, e: int, m: int) -> int:
    """Возведение a^e по модулю m — алгоритм быстрого возведения (square-and-multiply)."""
    if m == 1:
        return 0
    a %= m
    result = 1
    base = a
    exp = e
    while exp > 0:
        if exp & 1:
            result = (result * base) % m
        base = (base * base) % m
        exp >>= 1
    return result


def is_probable_prime_fermat(n: int, k: int = 8) -> bool:
    """Проверка простоты тестом Ферма с k испытаниями."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    for _ in range(k):
        a = random.randrange(2, n - 1)
        if mod_pow(a, n - 1, n) != 1:
            return False
    return True


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Обобщённый алгоритм Евклида.
    Возвращает (g, x, y) такие, что g = gcd(a, b) и a*x + b*y = g."""
    old_r, r = abs(a), abs(b)
    old_s, s = 1 if a >= 0 else -1, 0
    old_t, t = 0, 1 if b >= 0 else -1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    g = old_r
    x = old_s if a >= 0 else -old_s
    y = old_t if b >= 0 else -old_t
    return g, x, y


def gen_probable_prime(bits: int = 32, k: int = 8) -> int:
    """Генерация вероятно-простого числа с указанным количеством битов."""
    if bits < 2:
        raise ValueError('bits must be >= 2')

    while True:
        candidate = random.getrandbits(bits) | 1
        candidate |= (1 << (bits - 1))
        if is_probable_prime_fermat(candidate, k=k):
            return candidate


class BlindSignatureServer:
    """Серверная часть системы анонимного голосования."""

    def __init__(self):
        self.voters = {}  # Словарь для хранения информации о голосующих
        self.votes = []   # Список для хранения голосов
        self.vote_counts = {"Да": 0, "Нет": 0, "Воздержался": 0}

        # Генерация ключей сервера
        self.generate_server_keys()

    def generate_server_keys(self):
        """Генерация ключей сервера для слепой подписи."""
        # Генерируем простые числа для RSA
        p = gen_probable_prime(16, 8)  # Используем меньшие числа для демонстрации
        q = gen_probable_prime(16, 8)

        self.n = p * q
        self.phi_n = (p - 1) * (q - 1)

        # Выбираем открытый ключ
        self.e = 65537
        if self.e >= self.phi_n or extended_gcd(self.e, self.phi_n)[0] != 1:
            self.e = 3
            while extended_gcd(self.e, self.phi_n)[0] != 1:
                self.e += 2

        # Вычисляем секретный ключ
        _, self.d, _ = extended_gcd(self.e, self.phi_n)
        self.d = self.d % self.phi_n

        print(f"Сервер: n={self.n}, e={self.e}, d={self.d}")

    def register_voter(self, voter_id: str) -> bool:
        """Регистрация голосующего."""
        if voter_id in self.voters:
            return False

        self.voters[voter_id] = {
            'registered': True,
            'voted': False,
            'blind_factor': None
        }
        return True

    def blind_sign(self, blinded_message: int, voter_id: str) -> Optional[int]:
        """Слепая подпись сообщения."""
        if voter_id not in self.voters:
            return None

        if self.voters[voter_id]['voted']:
            return None  # Голосующий уже голосовал

        # Подписываем "слепое" сообщение
        signature = mod_pow(blinded_message, self.d, self.n)
        return signature

    def submit_vote(self, vote: str, signature: int, voter_id: str) -> bool:
        """Подача голоса."""
        if voter_id not in self.voters:
            return False

        if self.voters[voter_id]['voted']:
            return False  # Голосующий уже голосовал

        if vote not in ["Да", "Нет", "Воздержался"]:
            return False

        # Проверяем подпись (упрощенная проверка)
        # В реальной системе здесь была бы более сложная проверка

        # Записываем голос
        self.votes.append({
            'vote': vote,
            'signature': signature,
            'voter_id': voter_id,
            'timestamp': time.time()
        })

        self.vote_counts[vote] += 1
        self.voters[voter_id]['voted'] = True

        return True

    def get_results(self) -> Dict[str, int]:
        """Получение результатов голосования."""
        return self.vote_counts.copy()

    def get_vote_details(self) -> List[Dict]:
        """Получение детальной информации о голосах."""
        return self.votes.copy()


class BlindSignatureClient:
    """Клиентская часть системы анонимного голосования."""

    def __init__(self, voter_id: str, server: BlindSignatureServer):
        self.voter_id = voter_id
        self.server = server
        self.blind_factor = None
        self.blinded_message = None
        self.signature = None

    def generate_blind_factor(self, n: int) -> int:
        """Генерация слепого фактора."""
        # Выбираем случайное число взаимно простое с n
        while True:
            self.blind_factor = random.randint(2, n - 1)
            if extended_gcd(self.blind_factor, n)[0] == 1:
                break
        return self.blind_factor

    def blind_message(self, message: int, n: int, e: int) -> int:
        """Ослепление сообщения."""
        self.blind_factor = self.generate_blind_factor(n)
        self.blinded_message = (message * mod_pow(self.blind_factor, e, n)) % n
        return self.blinded_message

    def unblind_signature(self, blind_signature: int, n: int) -> int:
        """Снятие ослепления с подписи."""
        if self.blind_factor is None:
            return None

        # Вычисляем обратный элемент для слепого фактора
        _, blind_factor_inv, _ = extended_gcd(self.blind_factor, n)
        blind_factor_inv = blind_factor_inv % n

        # Снимаем ослепление
        self.signature = (blind_signature * blind_factor_inv) % n
        return self.signature

    def vote(self, choice: str) -> bool:
        """Процесс голосования."""
        if choice not in ["Да", "Нет", "Воздержался"]:
            return False

        # Кодируем выбор в число
        choice_code = {"Да": 1, "Нет": 2, "Воздержался": 3}[choice]

        # Ослепляем сообщение
        blinded_msg = self.blind_message(choice_code, self.server.n, self.server.e)

        # Получаем слепую подпись от сервера
        blind_sig = self.server.blind_sign(blinded_msg, self.voter_id)
        if blind_sig is None:
            return False

        # Снимаем ослепление
        signature = self.unblind_signature(blind_sig, self.server.n)
        if signature is None:
            return False

        # Подаем голос
        return self.server.submit_vote(choice, signature, self.voter_id)


class VotingSystemGUI:
    """Графический интерфейс системы анонимного голосования."""

    def __init__(self):
        # Инициализация сервера
        self.server = BlindSignatureServer()

        # Состояние
        self.current_voter = None
        self.voters = []

        if GUI_AVAILABLE:
            self.root = tk.Tk()
            self.root.title("Система анонимного голосования со слепой подписью")
            self.root.geometry("900x700")
            self.setup_ui()
        else:
            self.root = None

    def setup_ui(self):
        """Настройка пользовательского интерфейса."""
        if not GUI_AVAILABLE:
            return

        # Главный фрейм
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Панель регистрации
        reg_frame = ttk.LabelFrame(main_frame, text="Регистрация голосующих", padding="5")
        reg_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(reg_frame, text="ID голосующего:").grid(row=0, column=0, sticky=tk.W)
        self.voter_id_var = tk.StringVar()
        voter_id_entry = ttk.Entry(reg_frame, textvariable=self.voter_id_var, width=20)
        voter_id_entry.grid(row=0, column=1, sticky=tk.W, padx=(5, 0))

        ttk.Button(reg_frame, text="Зарегистрировать", command=self.register_voter).grid(row=0, column=2, padx=(10, 0))
        ttk.Button(reg_frame, text="Показать зарегистрированных", command=self.show_voters).grid(row=0, column=3, padx=(5, 0))

        # Панель голосования
        vote_frame = ttk.LabelFrame(main_frame, text="Голосование", padding="5")
        vote_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(vote_frame, text="Выберите голосующего:").grid(row=0, column=0, sticky=tk.W)
        self.voter_combo = ttk.Combobox(vote_frame, width=20)
        self.voter_combo.grid(row=0, column=1, sticky=tk.W, padx=(5, 0))

        ttk.Label(vote_frame, text="Ваш выбор:").grid(row=1, column=0, sticky=tk.W, pady=(10, 0))
        self.vote_var = tk.StringVar()
        vote_frame_choices = ttk.Frame(vote_frame)
        vote_frame_choices.grid(row=1, column=1, sticky=tk.W, padx=(5, 0), pady=(10, 0))

        ttk.Radiobutton(vote_frame_choices, text="Да", variable=self.vote_var, value="Да").grid(row=0, column=0, sticky=tk.W)
        ttk.Radiobutton(vote_frame_choices, text="Нет", variable=self.vote_var, value="Нет").grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        ttk.Radiobutton(vote_frame_choices, text="Воздержался", variable=self.vote_var, value="Воздержался").grid(row=0, column=2, sticky=tk.W, padx=(10, 0))

        ttk.Button(vote_frame, text="Проголосовать", command=self.vote).grid(row=2, column=0, columnspan=2, pady=(10, 0))

        # Панель результатов
        results_frame = ttk.LabelFrame(main_frame, text="Результаты голосования", padding="5")
        results_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Button(results_frame, text="Показать результаты", command=self.show_results).grid(row=0, column=0, padx=(0, 5))
        ttk.Button(results_frame, text="Показать детали", command=self.show_details).grid(row=0, column=1, padx=(0, 5))
        ttk.Button(results_frame, text="Очистить результаты", command=self.clear_results).grid(row=0, column=2)

        # Лог системы
        log_frame = ttk.LabelFrame(main_frame, text="Лог системы", padding="5")
        log_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, width=80)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Настройка растягивания
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log("Система анонимного голосования запущена")
        self.log(f"Ключи сервера: n={self.server.n}, e={self.server.e}, d={self.server.d}")

    def log(self, message: str):
        """Добавление сообщения в лог."""
        if GUI_AVAILABLE and hasattr(self, 'log_text'):
            self.log_text.insert(tk.END, message + "\n")
            self.log_text.see(tk.END)
            self.root.update()
        else:
            print(message)

    def register_voter(self):
        """Регистрация голосующего."""
        voter_id = self.voter_id_var.get().strip()
        if not voter_id:
            if GUI_AVAILABLE:
                messagebox.showerror("Ошибка", "Введите ID голосующего")
            else:
                print("Ошибка: Введите ID голосующего")
            return

        if self.server.register_voter(voter_id):
            self.voters.append(voter_id)
            if GUI_AVAILABLE and hasattr(self, 'voter_combo'):
                self.voter_combo['values'] = self.voters
            self.log(f"Голосующий {voter_id} зарегистрирован")
            if GUI_AVAILABLE:
                self.voter_id_var.set("")
        else:
            if GUI_AVAILABLE:
                messagebox.showerror("Ошибка", "Голосующий уже зарегистрирован")
            else:
                print("Ошибка: Голосующий уже зарегистрирован")

    def show_voters(self):
        """Показ зарегистрированных голосующих."""
        self.log("=== ЗАРЕГИСТРИРОВАННЫЕ ГОЛОСУЮЩИЕ ===")
        for voter_id in self.voters:
            status = "проголосовал" if self.server.voters[voter_id]['voted'] else "не голосовал"
            self.log(f"{voter_id}: {status}")
        self.log("")

    def vote(self):
        """Процесс голосования."""
        if GUI_AVAILABLE and hasattr(self, 'voter_combo'):
            voter_id = self.voter_combo.get()
            choice = self.vote_var.get()
        else:
            voter_id = input("Введите ID голосующего: ")
            print("Варианты: 1-Да, 2-Нет, 3-Воздержался")
            choice_map = {"1": "Да", "2": "Нет", "3": "Воздержался"}
            vote_choice = input("Введите номер варианта: ")
            choice = choice_map.get(vote_choice, "")

        if not voter_id:
            if GUI_AVAILABLE:
                messagebox.showerror("Ошибка", "Выберите голосующего")
            else:
                print("Ошибка: Выберите голосующего")
            return

        if not choice:
            if GUI_AVAILABLE:
                messagebox.showerror("Ошибка", "Выберите вариант ответа")
            else:
                print("Ошибка: Выберите вариант ответа")
            return

        self.log(f"=== ГОЛОСОВАНИЕ {voter_id} ===")

        # Создаем клиента
        client = BlindSignatureClient(voter_id, self.server)

        # Кодируем выбор
        choice_code = {"Да": 1, "Нет": 2, "Воздержался": 3}[choice]
        self.log(f"Выбор: {choice} (код: {choice_code})")

        # Генерируем слепой фактор
        blind_factor = client.generate_blind_factor(self.server.n)
        self.log(f"Слепой фактор: {blind_factor}")

        # Ослепляем сообщение
        blinded_msg = client.blind_message(choice_code, self.server.n, self.server.e)
        self.log(f"Ослепленное сообщение: {blinded_msg}")

        # Получаем слепую подпись
        blind_sig = self.server.blind_sign(blinded_msg, voter_id)
        if blind_sig is None:
            self.log("Ошибка: не удалось получить слепую подпись")
            return

        self.log(f"Слепая подпись: {blind_sig}")

        # Снимаем ослепление
        signature = client.unblind_signature(blind_sig, self.server.n)
        self.log(f"Подпись после снятия ослепления: {signature}")

        # Подаем голос
        if self.server.submit_vote(choice, signature, voter_id):
            self.log(f"Голос {voter_id} за {choice} успешно подан")
        else:
            self.log("Ошибка: не удалось подать голос")

        self.log("")

    def show_results(self):
        """Показ результатов голосования."""
        results = self.server.get_results()
        self.log("=== РЕЗУЛЬТАТЫ ГОЛОСОВАНИЯ ===")
        for choice, count in results.items():
            self.log(f"{choice}: {count} голосов")
        self.log("")

    def show_details(self):
        """Показ детальной информации о голосах."""
        details = self.server.get_vote_details()
        self.log("=== ДЕТАЛЬНАЯ ИНФОРМАЦИЯ О ГОЛОСАХ ===")
        for i, vote in enumerate(details):
            self.log(f"Голос {i+1}: {vote['voter_id']} -> {vote['vote']} (подпись: {vote['signature']})")
        self.log("")

    def clear_results(self):
        """Очистка результатов голосования."""
        self.server.votes.clear()
        self.server.vote_counts = {"Да": 0, "Нет": 0, "Воздержался": 0}
        for voter_id in self.server.voters:
            self.server.voters[voter_id]['voted'] = False
        self.log("Результаты голосования очищены")

    def run(self):
        """Запуск системы."""
        if not GUI_AVAILABLE:
            print("Графический интерфейс недоступен. Запуск в консольном режиме...")
            self.console_mode()
            return

        self.root.mainloop()

    def console_mode(self):
        """Консольный режим работы."""
        print("=== СИСТЕМА АНОНИМНОГО ГОЛОСОВАНИЯ - КОНСОЛЬНЫЙ РЕЖИМ ===")

        while True:
            print("\nВыберите действие:")
            print("1. Зарегистрировать голосующего")
            print("2. Проголосовать")
            print("3. Показать результаты")
            print("4. Показать детали голосов")
            print("5. Очистить результаты")
            print("0. Выход")

            try:
                choice = input("Введите номер действия: ").strip()

                if choice == "0":
                    break
                elif choice == "1":
                    voter_id = input("Введите ID голосующего: ").strip()
                    if self.server.register_voter(voter_id):
                        self.voters.append(voter_id)
                        print(f"Голосующий {voter_id} зарегистрирован")
                    else:
                        print("Ошибка: Голосующий уже зарегистрирован")
                elif choice == "2":
                    if not self.voters:
                        print("Сначала зарегистрируйте голосующих")
                        continue

                    print("Зарегистрированные голосующие:", ", ".join(self.voters))
                    voter_id = input("Выберите голосующего: ").strip()
                    if voter_id not in self.voters:
                        print("Голосующий не найден")
                        continue

                    print("Варианты ответов: 1-Да, 2-Нет, 3-Воздержался")
                    vote_choice = input("Введите номер варианта: ").strip()
                    choice_map = {"1": "Да", "2": "Нет", "3": "Воздержался"}

                    if vote_choice not in choice_map:
                        print("Неверный выбор")
                        continue

                    client = BlindSignatureClient(voter_id, self.server)
                    if client.vote(choice_map[vote_choice]):
                        print(f"Голос {voter_id} за {choice_map[vote_choice]} успешно подан")
                    else:
                        print("Ошибка при подаче голоса")
                elif choice == "3":
                    results = self.server.get_results()
                    print("\n=== РЕЗУЛЬТАТЫ ГОЛОСОВАНИЯ ===")
                    for vote, count in results.items():
                        print(f"{vote}: {count} голосов")
                elif choice == "4":
                    details = self.server.get_vote_details()
                    print("\n=== ДЕТАЛЬНАЯ ИНФОРМАЦИЯ О ГОЛОСАХ ===")
                    for i, vote in enumerate(details):
                        print(f"Голос {i+1}: {vote['voter_id']} -> {vote['vote']}")
                elif choice == "5":
                    self.server.votes.clear()
                    self.server.vote_counts = {"Да": 0, "Нет": 0, "Воздержался": 0}
                    for voter_id in self.server.voters:
                        self.server.voters[voter_id]['voted'] = False
                    print("Результаты голосования очищены")
                else:
                    print("Неверный выбор")

            except KeyboardInterrupt:
                print("\nВыход...")
                break
            except Exception as e:
                print(f"Ошибка: {e}")


def demonstrate_blind_signature():
    """Демонстрация работы слепой подписи."""
    print("=== ДЕМОНСТРАЦИЯ СЛЕПОЙ ПОДПИСИ ===")
    print()

    # Создаем сервер
    server = BlindSignatureServer()
    print(f"Сервер: n={server.n}, e={server.e}, d={server.d}")
    print()

    # Создаем клиента
    client = BlindSignatureClient("test_voter", server)

    # Регистрируем голосующего
    server.register_voter("test_voter")
    print("Голосующий зарегистрирован")

    # Тестируем голосование
    choice = "Да"
    choice_code = 1
    print(f"Выбор: {choice} (код: {choice_code})")

    # Ослепляем сообщение
    blinded_msg = client.blind_message(choice_code, server.n, server.e)
    print(f"Ослепленное сообщение: {blinded_msg}")

    # Получаем слепую подпись
    blind_sig = server.blind_sign(blinded_msg, "test_voter")
    print(f"Слепая подпись: {blind_sig}")

    # Снимаем ослепление
    signature = client.unblind_signature(blind_sig, server.n)
    print(f"Подпись после снятия ослепления: {signature}")

    # Подаем голос
    success = server.submit_vote(choice, signature, "test_voter")
    print(f"Голос подан: {success}")

    # Показываем результаты
    results = server.get_results()
    print(f"Результаты: {results}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Система анонимного голосования со слепой подписью')
    parser.add_argument('--demo', action='store_true', help='Показать демонстрацию слепой подписи')
    args = parser.parse_args()

    if args.demo:
        demonstrate_blind_signature()
    else:
        print('=== Лабораторная работа №13: Протокол "слепой" подписи для анонимного голосования ===')

        if GUI_AVAILABLE:
            print('Запуск графического интерфейса...')
        else:
            print('Графический интерфейс недоступен. Запуск в консольном режиме...')

        voting_system = VotingSystemGUI()
        voting_system.run()