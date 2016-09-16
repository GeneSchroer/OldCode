package beans;

public class Trade {
	private int accountId;
	private int brokerId;
	private int transactionId;
	private int orderId;
	private String stockId;
	
	public Trade(int accountId, int brokerId, int transactionId, int orderId, String stockId){
		this.accountId = accountId;
		this.brokerId = brokerId;
		this.transactionId = transactionId;
		this.orderId = orderId;
		this.stockId = stockId;
	}
	
	public int getAccountId(){ return accountId; }
	public void setAccountId(int accountId){ this.accountId = accountId; }
	
	public int getBrokerId(){ return brokerId; }
	public void setBrokerId(int brokerId){ this.brokerId = brokerId; }
	
	public int getTransactionId(){ return transactionId; }
	public void setTransactionId(int transactionId){ this.transactionId = transactionId; }
	
	public int getOrderId(){ return orderId; }
	public void setOrder(int orderId){ this.orderId = orderId; }
	
	public String getStockId(){ return stockId; }
	public void setStockId(String stockId){ this.stockId = stockId; }
}

