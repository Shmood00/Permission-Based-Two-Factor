set @time_diff := (select timediff(current_timestamp(), (select verified_date from capstone.device where is_verified = 1)));

select @time_diff;

set @is_expired := (select if(@time_diff >= "00:30:00", "yes","no"));

select @is_expired;