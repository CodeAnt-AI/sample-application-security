from api_service import WalletService
import threading

wallet = WalletService()

def handle_transfer(sender, recipient, amount):
    # Multiple simultaneous calls can overdraw account
    # Thread 1: Check balance (1000) ✓
    # Thread 2: Check balance (1000) ✓  
    # Thread 1: Deduct 800 → Balance: 200
    # Thread 2: Deduct 800 → Balance: -600 ❌
    return wallet.transfer(sender, recipient, amount)