package beans;

import java.util.Date;

public class Account {
	private int id;
	private Date dateOpened;
	private int clientId;
	public Account(int id, Date dateOpened, int clientId){
		this.id = id;
		this.dateOpened = dateOpened;
		this.clientId = clientId;
	}
	public int getId(){ return id; }
	public void setId(int id){ this.id = id; }
	
	public Date getDateOpened(){ return dateOpened; }
	public void setDateOpened(Date dateOpened){ this.dateOpened = dateOpened; }
	
	public int getClientId(){ return clientId; }
	public void setClientId(int clientId){ this.clientId = clientId; }
}
	

