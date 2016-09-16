package beans;

import java.sql.Date;

public class Employee extends Person {
	
	private Integer id;
	private Date startDate;
	private Integer hourlyRate;
	public Employee(int SSN, String firstName, String lastName, String address, int zipCode, String telephone, int id, Date startDate, int hourlyRate){
		this.SSN = SSN;
		this.lastName = lastName;
		this.firstName = firstName;
		this.address = address;
		this.zipCode = zipCode;
		this.telephone = telephone;
		this.id = id;
		this.startDate = startDate;
		this.hourlyRate = hourlyRate;
	}
	public int getId(){ return id; }
	public void setId(int id){ this.id = id; }
	
	public Date getStartDate(){ return startDate; }
	public void setStartDate(Date startDate){ this.startDate = startDate; }
	
	public int getHourlyRate(){ return hourlyRate; }
	public void setHourlyRate(int hourlyRate){ this.hourlyRate = hourlyRate; }
	
}
