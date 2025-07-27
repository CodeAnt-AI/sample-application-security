class WalletService:
    def __init__(self):
        self.balances = {"user1": 1000, "user2": 500}
    
    def transfer(self, sender, recipient, amount):
        
        sender_balance = self.balances.get(sender, 0)
        
        if sender_balance >= amount:
            
            process_transaction()  
            
            
            self.balances[sender] -= amount
            self.balances[recipient] = self.balances.get(recipient, 0) + amount
            return True
        return False