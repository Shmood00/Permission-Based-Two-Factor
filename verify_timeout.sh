#!/bin/bash

results=$(mysql --login-path=local -D capstone -se "select owner_id from capstone.device where is_verified=1;")

if [ -z "$results" ]; then
	echo "No verified decives"
else
	for id in $results
	do
		verify_diff=$(mysql --login-path=local -D capstone -se "set @time_diff=(select timediff(current_timestamp(), (select verified_date from capstone.device where is_verified=1 and owner_id=$id)));select if(@time_diff >= '00:30:00', 'yes', 'no') as verification_expired;")
		
		if [ "$verify_diff" = "yes" ]; then
			echo "expired token"
			echo "Resetting is_verified value for the owner_id of $id"
			mysql --login-path=local -D capstone -se "update capstone.device set is_verified = 0, verified_date = null where is_verified = 1 and owner_id=$id;"
			echo "Done"
			echo ""
		else
			echo "owner_id of $id does not have an expired token"
			echo ""
		fi
	done
fi
