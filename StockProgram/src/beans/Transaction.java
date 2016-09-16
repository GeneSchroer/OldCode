package beans;

import java.util.Date;

public class Transaction {
	private int id;
	private float fee;
	private Date DateTime;
	private float pricePerShare;
	public Transaction(int id, float fee, Date DateTime, float pricePerShare){
		this.id = id;
		this.fee = fee;
		this.DateTime = DateTime;
		this.pricePerShare = pricePerShare;
	}
	public int getId(){ return id; }
	public void setId(int id){ this.id = id; }
	
	public float getFee(){ return fee; }
	public void setFee(float fee){ this.fee = fee; }
	
	public Date getDateTime(){ return DateTime; }
	public void setDateTime(Date DateTime){ this.DateTime = DateTime; }
	
	public float getPricePerShare(){ return pricePerShare; }
	public void setPricePerShare(float pricePerShare){ this.pricePerShare = pricePerShare; }
	
}
