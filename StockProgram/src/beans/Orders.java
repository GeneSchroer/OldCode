package beans;

import java.util.Date;

public class Orders {
	private int numShares;
	private float pricePerShare;
	private int id;
	private Date dateTime;
	private double percentage;
	private String price;
	private String order;
	
	public Orders(int numShares, float pricePerShare, int id, Date dateTime, double percentage, String price, String order){
		this.numShares = numShares;
		this.pricePerShare = pricePerShare;
		this.id = id;
		this.dateTime = dateTime;
		this.percentage = percentage;
		this.price = price;
		this.order = order;
	}
	
	public int getNumShares(){ return numShares; }
	public void setNumShares(int numShares){ this.numShares = numShares; }
	
	public float getPricePerShare(){ return pricePerShare; }
	public void setPricePerShare(float pricePerShare){ this.pricePerShare = pricePerShare; }
	
	public int getId(){ return id; }
	public void setId(int id){ this.id = id; }
	
	public Date getDateTime(){ return dateTime; }
	public void setDateTime(Date dateTime){ this.dateTime = dateTime; }
	
	public double getPercentage(){ return percentage; }
	public void setPercentage(double percentage){ this.percentage = percentage; }
	
	public String getPrice(){ return price; }
	public void setPrice(String price){ this.price = price; }
	
	public String getOrder(){ return order; }
	public void setOrder(String order){ this.order = order; }
	
	
}
