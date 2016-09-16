package beans;

public class Stock {
	private String stockSymbol;
	private String companyName;
	private String type;
	private Float pricePerShare;
	public Stock(){
	}
	public Stock(String stockSymbol, String companyName, String type, float pricePerShare){
		this.stockSymbol = stockSymbol;
		this.companyName = companyName;
		this.type = type;
		this.pricePerShare = pricePerShare;
	}
	public String getStockSymbol(){ return stockSymbol; }
	public void setStockSymbol(String stockSymbol){ this.stockSymbol = stockSymbol; }
	
	public String getCompanyName(){ return companyName;	}
	public void setCompanyName(String companyName){ this.companyName = companyName; }
	
	public String getType(){ return type; }
	public void setType(String type){ this.type = type; }
	
	public float getPricePerShare(){ return pricePerShare; }
	public void setPricePerShare(float pricePerShare){ this.pricePerShare = pricePerShare; }
	
}
