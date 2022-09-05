package com.Innovature.MovBook.entity;

import java.sql.Date;
import java.util.Objects;

import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.TemporalType;

import org.springframework.data.jpa.repository.Temporal;

public class User {
	
	
	public static enum Status{
		INACTIVE((byte)0),
		ACTIVE((byte)1);
		
		
		public final byte value;
		
		
		private status(byte value) {
			this.value = value;
		}
	}
	
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer UserId;
	private String name;
	private String email;
	private String password;
	private byte status;
	@Temporal(TemporalType.TIMESTAMP)
	private Date createDate;
	@Temporal(TemporalType.TIMESTAMP)
	private Date updateDate;
	
	public User() {
	}
	
	
	public User(Integer userId) {
		this.UserId = userId
	}
	
	public User(String name, String email, String password) {
		this.name = name;
		this.email = email;
		this.password = password;
		
		
		this.status = Status.ACTIVE.value;
		
		Date dt = new Date();
		this.createDate = createDate;
		this.updateDate = updateDate;
	}


	public Integer getUserId() {
		return UserId;
	}


	public void setUserId(Integer userId) {
		UserId = userId;
	}


	public String getName() {
		return name;
	}


	public void setName(String name) {
		this.name = name;
	}


	public String getEmail() {
		return email;
	}


	public void setEmail(String email) {
		this.email = email;
	}


	public String getPassword() {
		return password;
	}


	public void setPassword(String password) {
		this.password = password;
	}


	public byte getStatus() {
		return status;
	}


	public void setStatus(byte status) {
		this.status = status;
	}


	public Date getCreateDate() {
		return createDate;
	}


	public void setCreateDate(Date createDate) {
		this.createDate = createDate;
	}


	public Date getUpdateDate() {
		return updateDate;
	}


	public void setUpdateDate(Date updateDate) {
		this.updateDate = updateDate;
	}
	
	@Override
	public boolean equals(Object object) {
		if (!(object instanceof User)) {
			return false;
		}
		User other = (User) object;
		return Objects.equals(this,userId, other.userId);
	}
	
	@Override
	public String toString() {
		return "com.Innovature.MovBook.entity.User[userId=" + userId + "]";
	}
	public User update(UserForm form) {
		this.name = form.getName();
		this.email = form.getEmail();
		this.password = form.getPassword();
		Date dt = new Date();
		
		this.updateDate = dt;
		
	return this;
	}
}
