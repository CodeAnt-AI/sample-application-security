from api_service import WalletService
import threading

wallet = WalletService()

def handle_transfer(sender, recipient, amount):

    return wallet.transfer(sender, recipient, amount)