package beans;

public class Client extends Person {
	private String email;
	private Integer rating;
	private String creditCardNumber;
	private Integer id;
	
	public Client(){
		super();
		this.email=null;
		this.rating=null;
		this.creditCardNumber=null;
		this.id=null;
	}
	
	public Client(int SSN, String firstName, String lastName, String address, int zipCode, String telephone, String email, int rating, String creditCardNumber){
		super(SSN, firstName, lastName, address, zipCode, telephone);
/*		this.SSN = SSN;
		this.firstName = firstName;
		this.lastName = lastName;
		this.address = address;
		this.zipCode = zipCode;
		this.telephone = telephone;*/
		this.email = email;
		this.rating = rating;
		this.creditCardNumber = creditCardNumber;
		this.id = SSN;
	}
	
	public String getEmail(){ return email; }
	public void setEmail(String email){ this.email = email; }
	
	public Integer getRating(){ return rating; }
	public void setRating(int rating){ this.rating = rating; }
	
	public String getCreditCardNumber(){ return creditCardNumber; }
	public void setCreditCardNumber(String creditCardNumber){ this.creditCardNumber = creditCardNumber; }
	
	public Integer getId(){ return id; }
	public void setId(int id){ this.id = id; }
	
}
