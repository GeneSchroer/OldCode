package beans;

public class Person {

	protected Integer SSN;
	protected String lastName;
	protected String firstName;
	protected String address;
	protected Integer zipCode;
	protected String telephone;
	public Person(){
		this.SSN = null;
		this.lastName = null;
		this.firstName=null;
		this.address=null;
		this.zipCode=null;
		this.telephone=null;
	}
	public Person(int SSN, String lastName, String firstName, String address, int zipCode, String telephone){
		this.SSN = SSN;
		this.lastName = lastName;
		this.firstName = firstName;
		this.address = address;
		this.zipCode = zipCode;
		this.telephone = telephone;
	}
	public int getSSN(){ return SSN; }
	public void setSSN(int SSN){ this.SSN = SSN; }
	
	public String getLastName(){ return lastName; }
	public void setLastName(String lastName){ this.lastName = lastName; }
	public String getFirstName(){ return firstName; }
	public void setFirstName(String firstName){ this.firstName = firstName; }
	public String getAddress(){ return address; }
	public void setAddress(String address){ this.address = address; }
	public Integer getZipCode(){ return zipCode; }
	public void setZipCode(int zipCode){ this.zipCode = zipCode; }
	public String getTelephone(){ return telephone; }
	public void setTelephone(String telephone ){ this.telephone = telephone; }

	
}
