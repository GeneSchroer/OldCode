package beans;

public class MailingList {
	private String name;
	private String email;
	private String address;
	private String city;
	private String state;
	private Integer zipCode;
	public MailingList(String name, String email, String address, String city, String state, int zipCode){
		this.name = name;
		this.email = email;
		this.address = address;
		this.city = city;
		this.state = state;
		this.zipCode = zipCode;
		
	}
	public String getName(){ return name; }
	public void setName(String name){ this.name = name; }
	
	public String getEmail(){ return email; }
	public void setEmail(String email){ this.email= email; }
	
	public String getAddress(){ return address; }
	public void setAddress(String address){ this.address = address; }
	
	public String getCity(){ return city; }
	public void setCity(String city){ this.city = city; }
	
	public String getState(){ return state; }
	public void setState(String state){ this.state = state; }
	
	public Integer getZipCode(){ return zipCode; }
	public void setZipCode(int zipCode){ this.zipCode = zipCode; }
}
