package beans;

public class Portfolio {
	String id=null;
	String stockSymbol=null;
	Integer totalShares=null;
	
	public Portfolio(String id, String stockSymbol, int totalShares) {
		this.id=id;
		this.stockSymbol=stockSymbol;
		this.totalShares=totalShares;
	}
	
	public String getId(){ return id; }
	public void setId(String id){ this.id = id; }
	
	public String getStockSymbol(){ return stockSymbol; }
	public void setStockSymbol(String stockSymbol){ this.stockSymbol = stockSymbol; }
	
	public int getTotalShares(){ return totalShares; }
	public void setTotalShares(int totalShares){ this.totalShares = totalShares; }

}
